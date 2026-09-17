package masreg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/httpdiag"
	"github.com/TeleCrypt-io/controlplane/internal/registrationfailure"
)

func TestValidateSameOrigin(t *testing.T) {
	tests := []struct {
		name   string
		base   string
		target string
		want   bool
	}{
		{name: "same origin with MAS path", base: "https://backend.example/auth", target: "https://backend.example/", want: true},
		{name: "default HTTPS port", base: "https://backend.example", target: "https://backend.example:443", want: true},
		{name: "IPv6 and explicit port", base: "https://[2001:db8::1]:8448/auth", target: "https://[2001:db8::1]:8448", want: true},
		{name: "IPv6 different port", base: "https://[2001:db8::1]:8448/auth", target: "https://[2001:db8::1]:443", want: false},
		{name: "different host", base: "https://backend.example", target: "https://evil.example", want: false},
		{name: "different scheme", base: "https://backend.example/auth", target: "http://backend.example", want: false},
		{name: "empty host", base: "https://:443/auth", target: "https://:443", want: false},
		{name: "backend path", base: "https://backend.example", target: "https://backend.example/auth", want: false},
		{name: "backend query", base: "https://backend.example", target: "https://backend.example/?token=leak", want: false},
		{name: "backend credentials", base: "https://backend.example", target: "https://user:password@backend.example", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validateSameOrigin(test.base, test.target) == nil; got != test.want {
				t.Fatalf("validateSameOrigin(%q, %q) = %t, want %t", test.base, test.target, got, test.want)
			}
		})
	}
}

func TestRegisterAndAuthorizeDeviceRejectsInvalidInputsBeforeHTTP(t *testing.T) {
	client := NewClient("https://backend.example/auth")
	for _, test := range []struct {
		name, username, password, deviceID string
	}{
		{name: "username", username: "Alice", password: "generated-password", deviceID: "DEVICE-123"},
		{name: "password", username: "alice", password: "bad\npassword", deviceID: "DEVICE-123"},
		{name: "device", username: "alice", password: "generated-password", deviceID: "DEVICE/123"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := client.RegisterAndAuthorizeDevice(
				context.Background(), test.username, test.password, test.deviceID, "https://backend.example",
			)
			if err == nil || registrationfailure.Code(err) != "internal/invariant" {
				t.Fatalf("RegisterAndAuthorizeDevice error = %v, want input rejection", err)
			}
		})
	}
}

func TestRegistrationRedirectPolicy(t *testing.T) {
	base, err := url.Parse("https://[2001:db8::1]:8448/auth")
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	policy := registrationRedirectPolicy(base)
	request := func(method, target string) *http.Request {
		t.Helper()
		req, requestErr := http.NewRequest(method, target, nil)
		if requestErr != nil {
			t.Fatalf("new request: %v", requestErr)
		}
		return req
	}
	next := func(target string, status int) *http.Request {
		t.Helper()
		req, requestErr := http.NewRequest(http.MethodGet, target, nil)
		if requestErr != nil {
			t.Fatalf("new redirect request: %v", requestErr)
		}
		req.Response = &http.Response{StatusCode: status}
		return req
	}

	valid := []struct{ method, from, to string }{
		{http.MethodGet, "/register", "/register/password"},
		{http.MethodPost, "/register/password", "/register/steps/01J00000000000000000000000/finish"},
		{http.MethodGet, "/register/steps/01J00000000000000000000000/finish", "/register/steps/01J00000000000000000000000/display-name"},
		{http.MethodPost, "/register/steps/01J00000000000000000000000/display-name", "/register/steps/01J00000000000000000000000/finish"},
		{http.MethodGet, "/register/steps/01J00000000000000000000000/finish", "/welcome"},
		{http.MethodPost, "/link", "/device/01J00000000000000000000000"},
	}
	for _, test := range valid {
		from := "https://[2001:db8::1]:8448/auth" + test.from
		to := "https://[2001:db8::1]:8448/auth" + test.to
		if err := policy(next(to, http.StatusSeeOther), []*http.Request{request(test.method, from)}); err != nil {
			t.Errorf("valid %s %s -> %s rejected: %v", test.method, test.from, test.to, err)
		}
	}

	invalid := []struct {
		name      string
		status    int
		from, to  string
		wantError string
	}{
		{name: "temporary redirect", status: http.StatusTemporaryRedirect, from: "/register/password", to: "/register/steps/id/finish", wantError: "body-preserving"},
		{name: "permanent redirect", status: http.StatusPermanentRedirect, from: "/register/password", to: "/register/steps/id/finish", wantError: "body-preserving"},
		{name: "found redirect", status: http.StatusFound, from: "/register/password", to: "/register/steps/id/finish", wantError: "requires a 303"},
		{name: "wrong port", status: http.StatusSeeOther, from: "/register", to: "https://[2001:db8::1]:8449/auth/register/password", wantError: "outside"},
		{name: "wrong scheme", status: http.StatusSeeOther, from: "/register", to: "http://[2001:db8::1]:8448/auth/register/password", wantError: "outside"},
		{name: "encoded path", status: http.StatusSeeOther, from: "/register", to: "https://[2001:db8::1]:8448/auth/%72egister/password", wantError: "unsafe"},
		{name: "query", status: http.StatusSeeOther, from: "/register", to: "https://[2001:db8::1]:8448/auth/register/password?next=secret", wantError: "unsafe"},
		{name: "unexpected path", status: http.StatusSeeOther, from: "/register/password", to: "/oauth2/token", wantError: "expected flow"},
		{name: "fabricated device completion", status: http.StatusSeeOther, from: "/device/01J00000000000000000000000", to: "/device/complete", wantError: "expected flow"},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			from := "https://[2001:db8::1]:8448/auth" + test.from
			to := test.to
			if strings.HasPrefix(to, "/") {
				to = "https://[2001:db8::1]:8448/auth" + to
			}
			err := policy(next(to, test.status), []*http.Request{request(http.MethodPost, from)})
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("policy error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func runRegistration(t *testing.T, baseURL string) error {
	t.Helper()
	_, err := NewClient(baseURL).RegisterAndAuthorizeDevice(
		context.Background(), "alice", "generated-password", "DEVICE-12345", baseURL,
	)
	return err
}

func TestRegisterAndAuthorizeDeviceMAS123Contract(t *testing.T) {
	var requests []string
	displayNameSubmitted := false
	var mas *httptest.Server
	mas = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/register":
			http.Redirect(w, r, "/register/password", http.StatusSeeOther)
		case r.Method == http.MethodGet && r.URL.Path == "/register/password":
			_, _ = w.Write([]byte(`<input name="csrf" value="register-csrf">`))
		case r.Method == http.MethodPost && r.URL.Path == "/register/password":
			if err := r.ParseForm(); err != nil {
				t.Errorf("password form: %v", err)
			}
			for field, want := range map[string]string{
				"csrf":             "register-csrf",
				"username":         "alice",
				"password":         "generated-password",
				"password_confirm": "generated-password",
				"accept_terms":     "on",
			} {
				if got := r.PostForm.Get(field); got != want {
					t.Errorf("password form %s = %q, want %q", field, got, want)
				}
			}
			http.Redirect(w, r, "/register/steps/account/finish", http.StatusSeeOther)
		case r.Method == http.MethodGet && r.URL.Path == "/register/steps/account/finish":
			if displayNameSubmitted {
				http.Redirect(w, r, "/", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/register/steps/account/display-name", http.StatusSeeOther)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/register/steps/account/display-name":
			_, _ = w.Write([]byte(`<input name="csrf" value="display-csrf">`))
		case r.Method == http.MethodPost && r.URL.Path == "/register/steps/account/display-name":
			if err := r.ParseForm(); err != nil {
				t.Errorf("display-name form: %v", err)
			}
			if got, want := r.PostForm.Get("csrf"), "display-csrf"; got != want {
				t.Errorf("display-name csrf = %q, want %q", got, want)
			}
			if got, want := r.PostForm.Get("action"), "skip"; got != want {
				t.Errorf("display-name action = %q, want %q", got, want)
			}
			displayNameSubmitted = true
			http.Redirect(w, r, "/register/steps/account/finish", http.StatusSeeOther)
		case r.Method == http.MethodGet && r.URL.Path == "/":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/oauth2/registration":
			var body struct {
				ClientURI               string   `json:"client_uri"`
				RedirectURIs            []string `json:"redirect_uris"`
				ApplicationType         string   `json:"application_type"`
				TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
				GrantTypes              []string `json:"grant_types"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("dynamic registration body: %v", err)
			}
			if body.ClientURI != mas.URL || len(body.RedirectURIs) != 1 || body.RedirectURIs[0] != mas.URL {
				t.Errorf("dynamic registration URIs = %q, %q, want %q", body.ClientURI, body.RedirectURIs, mas.URL)
			}
			if body.ApplicationType != "native" || body.TokenEndpointAuthMethod != "none" {
				t.Errorf("dynamic registration client settings = %#v", body)
			}
			for _, want := range []string{
				"urn:ietf:params:oauth:grant-type:device_code",
				"refresh_token",
			} {
				if !slices.Contains(body.GrantTypes, want) {
					t.Errorf("dynamic registration grant_types = %q, missing %q", body.GrantTypes, want)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"client_id":"client-123"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/oauth2/device":
			if err := r.ParseForm(); err != nil {
				t.Errorf("device form: %v", err)
			}
			if got, want := r.PostForm.Get("client_id"), "client-123"; got != want {
				t.Errorf("device client_id = %q, want %q", got, want)
			}
			if !strings.Contains(r.PostForm.Get("scope"), "urn:matrix:org.matrix.msc2967.client:device:DEVICE-12345") {
				t.Errorf("device scope = %q, want device grant", r.PostForm.Get("scope"))
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"device_code":"device-123","user_code":"user-123","expires_in":1200,"interval":1}`))
		case r.Method == http.MethodGet && r.URL.Path == "/link":
			if r.URL.RawQuery != "" {
				t.Errorf("device link GET query = %q, want no code auto-fill query", r.URL.RawQuery)
			}
			http.SetCookie(w, &http.Cookie{Name: "csrf", Value: "link-csrf", Path: "/"})
			_, _ = w.Write([]byte(`<input name="csrf" value="link-csrf">`))
		case r.Method == http.MethodPost && r.URL.Path == "/link":
			if err := r.ParseForm(); err != nil {
				t.Errorf("device link form: %v", err)
			}
			for field, want := range map[string]string{
				"csrf": "link-csrf",
				"code": "user-123",
			} {
				if got := r.PostForm.Get(field); got != want {
					t.Errorf("device link %s = %q, want %q", field, got, want)
				}
			}
			http.Redirect(w, r, "/device/device-123", http.StatusSeeOther)
		case r.Method == http.MethodGet && r.URL.Path == "/device/device-123":
			_, _ = w.Write([]byte(`<input name="csrf" value="consent-csrf">`))
		case r.Method == http.MethodPost && r.URL.Path == "/device/device-123":
			if err := r.ParseForm(); err != nil {
				t.Errorf("device consent form: %v", err)
			}
			for field, want := range map[string]string{
				"csrf":           "consent-csrf",
				"confirm_device": "on",
				"action":         "consent",
			} {
				if got := r.PostForm.Get(field); got != want {
					t.Errorf("device consent %s = %q, want %q", field, got, want)
				}
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>device linked</body></html>"))
		case r.Method == http.MethodPost && r.URL.Path == "/oauth2/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("token form: %v", err)
			}
			for field, want := range map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"device_code": "device-123",
				"client_id":   "client-123",
			} {
				if got := r.PostForm.Get(field); got != want {
					t.Errorf("token form %s = %q, want %q", field, got, want)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access-123","refresh_token":"refresh-123","expires_in":300}`))
		case r.Method == http.MethodGet && r.URL.Path == "/_matrix/client/v3/account/whoami":
			if got, want := r.Header.Get("Authorization"), "Bearer access-123"; got != want {
				t.Errorf("whoami authorization = %q, want %q", got, want)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user_id":"@alice:telecrypt.io","device_id":"DEVICE-12345"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer mas.Close()

	got, err := NewClient(mas.URL).RegisterAndAuthorizeDevice(
		context.Background(), "alice", "generated-password", "DEVICE-12345", mas.URL,
	)
	if err != nil {
		t.Fatalf("RegisterAndAuthorizeDevice: %v", err)
	}
	if got.AccessToken != "access-123" || got.RefreshToken != "refresh-123" || got.ClientID != "client-123" {
		t.Fatalf("tokens = %#v, want MAS 1.23 device result", got)
	}
	if got.UserID != "@alice:telecrypt.io" || got.Issuer != mas.URL+"/" || got.TokenEndpoint != mas.URL+"/oauth2/token" {
		t.Fatalf("identity metadata = %#v, want MAS 1.23 identity", got)
	}
	for _, want := range []string{
		"GET /register",
		"GET /register/password",
		"POST /register/password",
		"GET /register/steps/account/display-name",
		"POST /register/steps/account/display-name",
		"GET /register/steps/account/finish",
		"POST /oauth2/registration",
		"POST /oauth2/device",
		"GET /link",
		"POST /link",
		"GET /device/device-123",
		"POST /device/device-123",
		"POST /oauth2/token",
		"GET /_matrix/client/v3/account/whoami",
	} {
		if !slices.Contains(requests, want) {
			t.Errorf("request sequence is missing %q: %v", want, requests)
		}
	}
}

func TestMatrixIdentityValidationAndDeviceFlowBounds(t *testing.T) {
	for _, test := range []struct {
		name string
		user string
		dev  string
		want bool
	}{
		{name: "valid", user: "@alice:telecrypt.io", dev: "DEVICE-123", want: true},
		{name: "valid canonical localpart punctuation", user: "@alice/+_=-:telecrypt.io", dev: "DEVICE-123", want: true},
		{name: "user missing sigil", user: "alice:telecrypt.io", dev: "DEVICE-123", want: false},
		{name: "user whitespace", user: "@alice smith:telecrypt.io", dev: "DEVICE-123", want: false},
		{name: "foreign URL syntax", user: "@alice:telecrypt.io?token=leak", dev: "DEVICE-123", want: false},
		{name: "invalid server label", user: "@alice:telecrypt..io", dev: "DEVICE-123", want: false},
		{name: "valid IPv6 server", user: "@alice:[2001:db8::1]:8448", dev: "DEVICE-123", want: true},
		{name: "device punctuation", user: "@alice:telecrypt.io", dev: "DEVICE/123", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validMatrixUserID(test.user) && validMatrixDeviceID(test.dev); got != test.want {
				t.Fatalf("identity validation = %t, want %t", got, test.want)
			}
		})
	}
	state := &deviceAuthorization{DeviceCode: "device", UserCode: "user", ExpiresIn: 1201, Interval: 1}
	s := &session{baseURL: "https://mas.example"}
	if _, err := s.pollDeviceToken(context.Background(), "client", state); err == nil || registrationfailure.Code(err) != "device_token/invariant" {
		t.Fatal("pollDeviceToken accepted an overflowing device lifetime")
	}
}

func TestStartDeviceAuthorizationMASDeviceLifetimeBounds(t *testing.T) {
	for _, test := range []struct {
		name      string
		expiresIn int
		wantError bool
	}{
		{name: "MAS 1.23 maximum", expiresIn: 1200},
		{name: "over maximum", expiresIn: 1201, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/oauth2/device" {
					t.Fatalf("device authorization request = %s %s, want POST /oauth2/device", r.Method, r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"device_code":"device-123","user_code":"user-123","expires_in":%d,"interval":1}`, test.expiresIn)
			}))
			defer srv.Close()

			s := &session{baseURL: srv.URL, publicHTTPClient: srv.Client()}
			got, err := s.startDeviceAuthorization(context.Background(), "client-123", "DEVICE-123")
			if (err != nil) != test.wantError {
				t.Fatalf("startDeviceAuthorization error = %v, wantError %t", err, test.wantError)
			}
			if test.wantError {
				if got != nil || registrationfailure.Code(err) != "device_authorization/protocol" {
					t.Fatalf("startDeviceAuthorization result = %#v, error = %v, want protocol rejection", got, err)
				}
				return
			}
			if got == nil || got.ExpiresIn != test.expiresIn {
				t.Fatalf("startDeviceAuthorization result = %#v, want expires_in %d", got, test.expiresIn)
			}
		})
	}
}

func TestPollDeviceTokenAcceptsMASDeviceLifetimeMaximum(t *testing.T) {
	transport := &flakyTransport{calls: 1, body: `{"access_token":"access","refresh_token":"refresh","expires_in":60}`}
	s := &session{
		baseURL:          "https://mas.example",
		publicHTTPClient: &http.Client{Transport: transport},
	}
	got, err := s.pollDeviceToken(context.Background(), "client", &deviceAuthorization{
		DeviceCode: "device", UserCode: "user", ExpiresIn: 1200, Interval: 1,
	})
	if err != nil || got == nil || got.AccessToken != "access" {
		t.Fatalf("pollDeviceToken at MAS maximum = %#v, error = %v, want successful token", got, err)
	}
}

func TestPollDeviceTokenBoundsAccessTokenLifetimeSeparately(t *testing.T) {
	for _, test := range []struct {
		name      string
		expiresIn int
		wantError bool
	}{
		{name: "maximum", expiresIn: int(maxMASAccessLifetime / time.Second)},
		{name: "over maximum", expiresIn: int(maxMASAccessLifetime/time.Second) + 1, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &flakyTransport{
				calls: 1,
				body: fmt.Sprintf(
					`{"access_token":"access","refresh_token":"refresh","expires_in":%d}`,
					test.expiresIn,
				),
			}
			s := &session{
				baseURL:          "https://mas.example",
				publicHTTPClient: &http.Client{Transport: transport},
			}
			got, err := s.pollDeviceToken(context.Background(), "client", &deviceAuthorization{
				DeviceCode: "code", UserCode: "user", ExpiresIn: 60, Interval: 1,
			})
			if (err != nil) != test.wantError {
				t.Fatalf("pollDeviceToken error = %v, wantError %t", err, test.wantError)
			}
			if !test.wantError && (got == nil || got.ExpiresIn != test.expiresIn) {
				t.Fatalf("pollDeviceToken result = %#v, want expires_in %d", got, test.expiresIn)
			}
		})
	}
}

func TestApproveDeviceAuthorizationRejectsUnexpectedSameOriginLanding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/auth/link":
			_, _ = w.Write([]byte(`<input name="csrf" value="link-csrf">`))
		case r.Method == http.MethodPost && r.URL.Path == "/auth/link":
			http.Redirect(w, r, "/auth/unexpected", http.StatusSeeOther)
		case r.Method == http.MethodGet && r.URL.Path == "/auth/unexpected":
			_, _ = w.Write([]byte(`<input name="csrf" value="unexpected-csrf">`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	base, err := url.Parse(srv.URL + "/auth")
	if err != nil {
		t.Fatalf("parse test base: %v", err)
	}
	s := &session{baseURL: base.String(), baseURLParsed: base, httpClient: &http.Client{CheckRedirect: registrationRedirectPolicy(base)}}
	err = s.approveDeviceAuthorization(context.Background(), "user-123")
	if err == nil || registrationfailure.Code(err) != "device_consent/protocol" {
		t.Fatalf("approveDeviceAuthorization error = %v, want unexpected same-origin landing rejection", err)
	}
}

func TestRegisterAndAuthorizeDeviceRejectsOffOriginRedirect(t *testing.T) {
	var offOriginRequests int
	offOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offOriginRequests++
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer offOrigin.Close()

	mas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/register" {
			t.Errorf("MAS received unexpected path %q", r.URL.Path)
		}
		http.Redirect(w, r, offOrigin.URL+"/register/password", http.StatusSeeOther)
	}))
	defer mas.Close()

	err := runRegistration(t, mas.URL)
	if err == nil || registrationfailure.Code(err) != "registration_form/protocol" {
		t.Fatalf("registration error = %v, want off-origin redirect rejection", err)
	}
	if offOriginRequests != 0 {
		t.Fatalf("off-origin server received %d requests; redirect must be rejected before credentials leave MAS", offOriginRequests)
	}
}

func TestRegisterAndAuthorizeDeviceRejectsOffOriginBackend(t *testing.T) {
	var requests int
	mas := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer mas.Close()

	_, err := NewClient(mas.URL).RegisterAndAuthorizeDevice(
		context.Background(), "alice", "generated-password", "DEVICE-12345", "https://backend.example",
	)
	if err == nil || registrationfailure.Code(err) != "internal/invariant" {
		t.Fatalf("registration error = %v, want same-origin rejection", err)
	}
	if requests != 0 {
		t.Fatalf("MAS received %d requests before off-origin backend rejection", requests)
	}
}

func TestPublicOAuthClientDoesNotUseAmbientProxy(t *testing.T) {
	s := &session{baseURL: "https://mas.example"}
	client := s.publicClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("public OAuth transport = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatalf("public OAuth transport proxy is enabled")
	}
}

func TestRegisterAndAuthorizeDeviceRejectsProviderChoicePage(t *testing.T) {
	var passwordPosts int
	mas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/register" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<input name="csrf" value="csrf">`))
		case r.Method == http.MethodPost:
			passwordPosts++
			http.Error(w, "unexpected password submission", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer mas.Close()

	err := runRegistration(t, mas.URL)
	if err == nil || registrationfailure.Code(err) != "registration_form/protocol" {
		t.Fatalf("registration error = %v, want provider-choice rejection", err)
	}
	if passwordPosts != 0 {
		t.Fatalf("password form received %d submissions after provider-choice page", passwordPosts)
	}
}

func TestRegisterAndAuthorizeDeviceRejectsIncompleteRegistrationAtBasePath(t *testing.T) {
	const prefix = "/auth"
	displayNameSubmitted := false
	mas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case prefix + "/register":
			if r.Method != http.MethodGet {
				t.Errorf("register request method = %s, want GET", r.Method)
			}
			http.Redirect(w, r, prefix+"/register/password", http.StatusSeeOther)
		case prefix + "/register/password":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<input name="csrf" value="csrf">`))
				return
			}
			http.Redirect(w, r, prefix+"/register/steps/one/finish", http.StatusSeeOther)
		case prefix + "/register/steps/one/display-name":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<input name="csrf" value="csrf">`))
				return
			}
			displayNameSubmitted = true
			http.Redirect(w, r, prefix+"/register/steps/one/finish", http.StatusSeeOther)
		case prefix + "/register/steps/one/finish":
			if displayNameSubmitted {
				_, _ = w.Write([]byte("still incomplete"))
			} else {
				http.Redirect(w, r, prefix+"/register/steps/one/display-name", http.StatusSeeOther)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer mas.Close()

	_, err := NewClient(mas.URL+prefix).RegisterAndAuthorizeDevice(
		context.Background(), "alice", "generated-password", "DEVICE-12345", mas.URL,
	)
	if err == nil || registrationfailure.Code(err) != "registration_display_name/protocol" {
		t.Fatalf("registration error = %v, want incomplete registration rejection", err)
	}
}

func TestOAuthRetriesHonorCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &session{baseURL: "http://127.0.0.1:1"}
	device := &deviceAuthorization{DeviceCode: "code", UserCode: "user", ExpiresIn: 60, Interval: 1}
	if _, err := s.pollDeviceToken(ctx, "client", device); !errors.Is(err, context.Canceled) || registrationfailure.Code(err) != "device_token/cancelled" {
		t.Fatalf("poll error = %v, want context canceled", err)
	}
	if _, _, err := s.whoAmI(ctx, "http://127.0.0.1:1", "token"); !errors.Is(err, context.Canceled) || registrationfailure.Code(err) != "identity/cancelled" {
		t.Fatalf("whoami error = %v, want context canceled", err)
	}
}

type flakyTransport struct {
	calls int
	body  string
}

type eventuallyReadyIdentityTransport struct {
	calls     int
	transient int
}

type timedIdentityTransport struct {
	calls int
	times []time.Time
}

type timeoutThenSuccessIdentityTransport struct {
	calls int
}

type errorTransport struct{ err error }

func (t errorTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }

type cancelOnCloseBody struct {
	io.Reader
	cancel context.CancelFunc
}

func (b *cancelOnCloseBody) Close() error {
	b.cancel()
	return nil
}

type retryCancelTransport struct {
	status int
	cancel context.CancelFunc
}

func (t retryCancelTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: t.status,
		Header:     make(http.Header),
		Body:       &cancelOnCloseBody{Reader: strings.NewReader("retry"), cancel: t.cancel},
	}, nil
}

type cancelRequestTransport struct{ cancel context.CancelFunc }

func (t cancelRequestTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.cancel()
	return nil, errors.New("transport error contains secret=must-not-escape")
}

type trackingBody struct {
	closed bool
}

func (b *trackingBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *trackingBody) Close() error {
	b.closed = true
	return nil
}

type responseBody struct {
	reader   io.Reader
	readErr  error
	closeErr error
}

func (b *responseBody) Read(p []byte) (int, error) {
	if b.readErr != nil {
		return 0, b.readErr
	}
	return b.reader.Read(p)
}

func (b *responseBody) Close() error { return b.closeErr }

type responseTransport struct {
	response *http.Response
	calls    int
}

func (t *responseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return t.response, nil
}

type unexpectedStatusTransport struct{ body *trackingBody }

func (t unexpectedStatusTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusBadRequest,
		Header:     make(http.Header),
		Body:       t.body,
	}, nil
}

func (t *flakyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	if t.calls == 1 {
		return nil, errors.New("temporary connection reset")
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(t.body)),
	}, nil
}

func (t *eventuallyReadyIdentityTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	status := http.StatusOK
	body := `{"user_id":"@agent:telecrypt.io","device_id":"DEVICE-12345"}`
	if t.calls <= t.transient {
		status = http.StatusNotFound
		body = "identity is not ready"
	}
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

func (t *timedIdentityTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	t.times = append(t.times, time.Now())
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("identity is not ready")),
	}, nil
}

func (t *timeoutThenSuccessIdentityTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	if t.calls == 1 {
		return nil, context.DeadlineExceeded
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"user_id":"@agent:telecrypt.io","device_id":"DEVICE-12345"}`)),
	}, nil
}

func TestOAuthRetriesTransientTransportErrors(t *testing.T) {
	tokenTransport := &flakyTransport{body: `{"access_token":"access","refresh_token":"refresh","expires_in":60}`}
	s := &session{baseURL: "https://mas.example", publicHTTPClient: &http.Client{Transport: tokenTransport}}
	got, err := s.pollDeviceToken(context.Background(), "client", &deviceAuthorization{DeviceCode: "code", UserCode: "user", ExpiresIn: 60, Interval: 1})
	if err != nil || got.AccessToken != "access" || tokenTransport.calls != 2 {
		t.Fatalf("poll result = %#v, err = %v, calls = %d", got, err, tokenTransport.calls)
	}

	whoamiTransport := &flakyTransport{body: `{"user_id":"@agent:telecrypt.io","device_id":"DEVICE-12345"}`}
	s.publicHTTPClient = &http.Client{Transport: whoamiTransport}
	userID, deviceID, err := s.whoAmI(context.Background(), "https://mas.example", "access")
	if err != nil || userID != "@agent:telecrypt.io" || deviceID != "DEVICE-12345" || whoamiTransport.calls != 2 {
		t.Fatalf("whoami result = %q, %q, %v, calls = %d", userID, deviceID, err, whoamiTransport.calls)
	}
}

func TestWhoAmIRetriesUntilProviderSuccess(t *testing.T) {
	transport := &eventuallyReadyIdentityTransport{transient: 6}
	s := &session{
		baseURL:          "https://mas.example",
		publicHTTPClient: &http.Client{Transport: transport},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	userID, deviceID, err := s.whoAmI(ctx, "https://mas.example", "access")
	if err != nil || userID != "@agent:telecrypt.io" || deviceID != "DEVICE-12345" || transport.calls != 7 {
		t.Fatalf("whoami result = %q, %q, %v, calls = %d", userID, deviceID, err, transport.calls)
	}
}

func TestWhoAmIStopsRetryingWhenCallerDeadlineExpires(t *testing.T) {
	transport := &eventuallyReadyIdentityTransport{transient: 100}
	s := &session{
		baseURL:          "https://mas.example",
		publicHTTPClient: &http.Client{Transport: transport},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, _, err := s.whoAmI(ctx, "https://mas.example", "access")
	if !errors.Is(err, context.DeadlineExceeded) || registrationfailure.Code(err) != "identity/timeout" {
		t.Fatalf("whoami error = %v, want identity/timeout wrapping deadline", err)
	}
	if transport.calls == 0 {
		t.Fatal("whoami did not issue an initial request")
	}
}

func TestWhoAmIRetryDelayIsCapped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := &timedIdentityTransport{}
		s := &session{
			baseURL:          "https://mas.example",
			publicHTTPClient: &http.Client{Transport: transport},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, _, err := s.whoAmI(ctx, "https://mas.example", "access")
		if !errors.Is(err, context.DeadlineExceeded) || registrationfailure.Code(err) != "identity/timeout" {
			t.Fatalf("whoami error = %v, want identity/timeout wrapping deadline", err)
		}
		if transport.calls < 3 {
			t.Fatalf("whoami calls = %d, want enough retries to reach capped backoff", transport.calls)
		}
		for i := 1; i < len(transport.times); i++ {
			if got := transport.times[i].Sub(transport.times[i-1]); got > identityRetryMaxDelay {
				t.Fatalf("retry delay %s exceeded cap %s", got, identityRetryMaxDelay)
			}
		}
		if got := transport.times[len(transport.times)-1].Sub(transport.times[len(transport.times)-2]); got != identityRetryMaxDelay {
			t.Fatalf("last retry delay = %s, want capped %s", got, identityRetryMaxDelay)
		}
	})
}

func TestWhoAmIRetriesPerRequestTimeout(t *testing.T) {
	transport := &timeoutThenSuccessIdentityTransport{}
	s := &session{
		baseURL:          "https://mas.example",
		publicHTTPClient: &http.Client{Transport: transport},
	}

	userID, deviceID, err := s.whoAmI(context.Background(), "https://mas.example", "access")
	if err != nil || userID != "@agent:telecrypt.io" || deviceID != "DEVICE-12345" || transport.calls != 2 {
		t.Fatalf("whoami result = %q, %q, %v, calls = %d", userID, deviceID, err, transport.calls)
	}
}

func TestWhoAmIDoesNotRetryUnauthorizedResponse(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	s := &session{baseURL: srv.URL, publicHTTPClient: srv.Client()}
	_, _, err := s.whoAmI(context.Background(), srv.URL, "access")
	if registrationfailure.Code(err) != "identity/upstream" {
		t.Fatalf("whoami error = %v, want identity/upstream", err)
	}
	if calls != 1 {
		t.Fatalf("whoami calls = %d, want one non-retried unauthorized request", calls)
	}
}

func TestPollDeviceTokenRejectsResponseDrainAndCloseFailures(t *testing.T) {
	drainErr := errors.New("response drain failed")
	closeErr := errors.New("response close failed")
	transport := &responseTransport{response: &http.Response{
		StatusCode: http.StatusBadGateway,
		Header:     make(http.Header),
		Body:       &responseBody{readErr: drainErr, closeErr: closeErr},
	}}
	s := &session{
		baseURL:          "https://mas.example",
		publicHTTPClient: &http.Client{Transport: transport},
	}

	_, err := s.pollDeviceToken(context.Background(), "client", &deviceAuthorization{
		DeviceCode: "code", UserCode: "user", ExpiresIn: 60, Interval: 1,
	})
	if registrationfailure.Code(err) != "device_token/protocol" || !errors.Is(err, drainErr) || !errors.Is(err, closeErr) {
		t.Fatalf("pollDeviceToken error = %v, want protocol with drain and close failures", err)
	}
	if transport.calls != 1 {
		t.Fatalf("pollDeviceToken calls = %d, want one after response cleanup failure", transport.calls)
	}
}

func TestUnexpectedStatusRetainsCompleteRawBody(t *testing.T) {
	secret := "access_token=device-token-secret"
	userID := "@customer:telecrypt.io"
	body := "provider detail " + secret + " " + userID + " tail"
	resp := &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader(body))}
	err := unexpectedStatus(resp)
	var diagnostic *httpdiag.ResponseError
	if !errors.As(err, &diagnostic) || diagnostic == nil || diagnostic.Body != body || !strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), userID) {
		t.Fatalf("unexpectedStatus error = %v, diagnostic = %#v, want complete raw body", err, diagnostic)
	}
}

func TestPollDeviceTokenRejectsSuccessfulResponseCloseFailure(t *testing.T) {
	closeErr := errors.New("response close failed")
	transport := &responseTransport{response: &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body: &responseBody{
			reader:   strings.NewReader(`{"access_token":"access","refresh_token":"refresh","expires_in":60}`),
			closeErr: closeErr,
		},
	}}
	s := &session{
		baseURL:          "https://mas.example",
		publicHTTPClient: &http.Client{Transport: transport},
	}

	got, err := s.pollDeviceToken(context.Background(), "client", &deviceAuthorization{
		DeviceCode: "code", UserCode: "user", ExpiresIn: 60, Interval: 1,
	})
	if got != nil || registrationfailure.Code(err) != "device_token/protocol" || !errors.Is(err, closeErr) {
		t.Fatalf("pollDeviceToken result = %#v, error = %v, want protocol close failure", got, err)
	}
}

func TestOAuthRetryCancellationPreservesDeviceTokenStage(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusBadGateway} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := &session{
				baseURL: "https://mas.example",
				publicHTTPClient: &http.Client{Transport: retryCancelTransport{
					status: status,
					cancel: cancel,
				}},
			}
			_, err := s.pollDeviceToken(ctx, "client", &deviceAuthorization{DeviceCode: "code", UserCode: "user", ExpiresIn: 60, Interval: 1})
			if !errors.Is(err, context.Canceled) || registrationfailure.Code(err) != "device_token/cancelled" {
				t.Fatalf("poll error = %v, want device_token/cancelled", err)
			}
		})
	}
}

func TestWhoAmICancellationPreservesIdentityStage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &session{
		baseURL:          "https://mas.example",
		publicHTTPClient: &http.Client{Transport: cancelRequestTransport{cancel: cancel}},
	}
	_, _, err := s.whoAmI(ctx, "https://mas.example", "access")
	if !errors.Is(err, context.Canceled) || registrationfailure.Code(err) != "identity/cancelled" {
		t.Fatalf("whoami error = %v, want identity/cancelled", err)
	}
}

func TestWhoAmIClosesBodyBeforeUnexpectedStatusReturn(t *testing.T) {
	body := &trackingBody{}
	s := &session{
		baseURL:          "https://mas.example",
		publicHTTPClient: &http.Client{Transport: unexpectedStatusTransport{body: body}},
	}
	_, _, err := s.whoAmI(context.Background(), "https://mas.example", "access")
	if err == nil || registrationfailure.Code(err) != "identity/upstream" {
		t.Fatalf("whoami error = %v, want identity/upstream", err)
	}
	if !body.closed {
		t.Fatal("whoami did not close response body before returning unexpected status")
	}
}

func TestWhoAmIPreservesResponseCloseFailure(t *testing.T) {
	closeErr := errors.New("identity response close failed")
	s := &session{
		baseURL: "https://mas.example",
		publicHTTPClient: &http.Client{Transport: &responseTransport{response: &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       &responseBody{reader: strings.NewReader(`{"user_id":"@agent:telecrypt.io","device_id":"DEVICE-12345"}`), closeErr: closeErr},
		}}},
	}
	_, _, err := s.whoAmI(context.Background(), "https://mas.example", "access")
	if registrationfailure.Code(err) != "identity/protocol" || !errors.Is(err, closeErr) {
		t.Fatalf("whoami error = %v, want identity/protocol with close failure", err)
	}
}

func TestSessionReusesPublicHTTPClient(t *testing.T) {
	s := &session{}
	first := s.publicClient()
	if first == nil {
		t.Fatal("publicClient returned nil")
	}
	if got := s.publicClient(); got != first {
		t.Fatal("publicClient allocated a new HTTP client for the same session")
	}
}

func TestMASRequestErrorsPreserveCompleteRawTransportText(t *testing.T) {
	const secret = "password=must-preserve"
	detail := strings.Repeat("diagnostic-", 7000) + " " + secret + " final-detail"
	s := &session{
		baseURL: "https://mas.example",
		publicHTTPClient: &http.Client{
			Transport: errorTransport{err: errors.New(detail)},
		},
	}
	_, err := s.registerPublicNativeClient(context.Background(), "https://mas.example")
	if err == nil {
		t.Fatal("registerPublicNativeClient returned nil error")
	}
	if !strings.Contains(err.Error(), detail) {
		t.Fatalf("registerPublicNativeClient did not preserve complete raw transport diagnostic: %v", err)
	}
}
