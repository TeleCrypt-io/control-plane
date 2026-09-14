package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TeleCrypt-io/controlplane/internal/masreg"
	"github.com/TeleCrypt-io/controlplane/internal/registrationfailure"
)

type fakeMASReg struct {
	result *masreg.DeviceTokens
	err    error
	calls  int
}

func (f *fakeMASReg) RegisterAndAuthorizeDevice(_ context.Context, username, _, _, _ string) (*masreg.DeviceTokens, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	result := *f.result
	if result.UserID == "" {
		result.UserID = "@" + username + ":telecrypt.io"
	}
	return &result, nil
}

func TestProvisionAgent_ReturnsRefreshableOAuthCredentials(t *testing.T) {
	m := &fakeMASReg{result: &masreg.DeviceTokens{
		AccessToken: "access", RefreshToken: "refresh", ExpiresIn: 3600,
		ClientID: "dynamic-client", Issuer: "https://mas.example/auth", TokenEndpoint: "https://mas.example/auth/oauth2/token",
	}}
	p, err := NewProvisioner(m, "https://backend.telecrypt.io", "telecrypt.io")
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	got, err := p.ProvisionAgent(context.Background())
	if err != nil {
		t.Fatalf("ProvisionAgent: %v", err)
	}
	if got.Password == "" || got.AccessToken != "access" || got.RefreshToken != "refresh" || got.ExpiresIn != 3600 {
		t.Fatalf("credential result = %#v, want password and complete refreshable token set", got)
	}
	if got.OAuthClientID != "dynamic-client" || got.OAuthIssuer != "https://mas.example/auth" || got.OAuthTokenEndpoint != "https://mas.example/auth/oauth2/token" {
		t.Fatalf("OAuth metadata = %#v", got)
	}
	if m.calls != 1 {
		t.Fatalf("MAS calls = %d, want 1", m.calls)
	}
}

func TestProvisionAgent_FailsClosed(t *testing.T) {
	p, err := NewProvisioner(&fakeMASReg{err: errors.New("MAS rejected registration")}, "https://backend.telecrypt.io", "telecrypt.io")
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	if _, err := p.ProvisionAgent(context.Background()); err == nil {
		t.Fatal("ProvisionAgent succeeded after MAS failure")
	}
}

func TestProvisionAgentRejectsForeignMXIDServer(t *testing.T) {
	m := &fakeMASReg{result: &masreg.DeviceTokens{UserID: "@agent:foreign.example"}}
	p, err := NewProvisioner(m, "https://backend.telecrypt.io", "telecrypt.io")
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	if _, err := p.ProvisionAgent(context.Background()); err == nil || registrationfailure.Code(err) != "identity/invariant" {
		t.Fatalf("ProvisionAgent foreign MXID error = %v, want exact-server rejection", err)
	}
}

// fakeMASServer models the complete supported public sequence. Its catch-all records any
// unsupported password-login or admin route, proving ProvisionAgent does not retain either path.
type fakeMASServer struct {
	csrf             string
	users            map[string]string
	registeredClient bool
	approved         bool
	displayNameDone  bool
	fallbackCalls    int
	deviceID         string
}

func newFakeMASServer() *fakeMASServer {
	return &fakeMASServer{csrf: "csrf", users: map[string]string{}}
}

func (f *fakeMASServer) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /register", f.registerGet)
	mux.HandleFunc("GET /register/password", f.passwordGet)
	mux.HandleFunc("POST /register/password", f.passwordPost)
	mux.HandleFunc("GET /register/steps/{id}/finish", f.finishGet)
	mux.HandleFunc("GET /register/steps/{id}/display-name", f.displayNameGet)
	mux.HandleFunc("POST /register/steps/{id}/display-name", f.displayNamePost)
	mux.HandleFunc("POST /oauth2/registration", f.clientRegister)
	mux.HandleFunc("POST /oauth2/device", f.deviceAuthorization)
	mux.HandleFunc("GET /link", f.linkGet)
	mux.HandleFunc("POST /link", f.linkPost)
	mux.HandleFunc("GET /device/device-123", f.deviceGet)
	mux.HandleFunc("POST /device/device-123", f.devicePost)
	mux.HandleFunc("POST /oauth2/token", f.tokenPost)
	mux.HandleFunc("GET /_matrix/client/v3/account/whoami", f.whoami)
	mux.HandleFunc("/", f.other)
	return httptest.NewServer(mux)
}

func (f *fakeMASServer) form(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "csrf", Value: f.csrf, Path: "/"})
	fmt.Fprintf(w, `<form><input name="csrf" value="%s"></form>`, f.csrf)
}

func (f *fakeMASServer) validCSRF(r *http.Request) bool {
	cookie, err := r.Cookie("csrf")
	return err == nil && cookie.Value == f.csrf && r.FormValue("csrf") == f.csrf
}

func (f *fakeMASServer) authenticated(r *http.Request) bool {
	cookie, err := r.Cookie("mas_session")
	return err == nil && cookie.Value == "registered"
}

func (f *fakeMASServer) registerGet(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/register/password", http.StatusSeeOther)
}
func (f *fakeMASServer) passwordGet(w http.ResponseWriter, _ *http.Request) { f.form(w) }
func (f *fakeMASServer) passwordPost(w http.ResponseWriter, r *http.Request) {
	if !f.validCSRF(r) {
		http.Error(w, "csrf", http.StatusBadRequest)
		return
	}
	f.users[r.FormValue("username")] = r.FormValue("password")
	http.Redirect(w, r, "/register/steps/a/finish", http.StatusSeeOther)
}
func (f *fakeMASServer) finishGet(w http.ResponseWriter, r *http.Request) {
	if f.displayNameDone {
		http.Redirect(w, r, "/welcome", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/register/steps/a/display-name", http.StatusSeeOther)
}
func (f *fakeMASServer) displayNameGet(w http.ResponseWriter, _ *http.Request) { f.form(w) }
func (f *fakeMASServer) displayNamePost(w http.ResponseWriter, r *http.Request) {
	if !f.validCSRF(r) {
		http.Error(w, "csrf", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "mas_session", Value: "registered", Path: "/"})
	f.displayNameDone = true
	http.Redirect(w, r, "/register/steps/a/finish", http.StatusSeeOther)
}
func (f *fakeMASServer) clientRegister(w http.ResponseWriter, r *http.Request) {
	var metadata map[string]any
	if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	grantTypes, ok := metadata["grant_types"].([]any)
	responseTypes, responseOK := metadata["response_types"].([]any)
	if _, hasSecret := metadata["client_secret"]; hasSecret || metadata["application_type"] != "native" || metadata["token_endpoint_auth_method"] != "none" || !ok || len(grantTypes) != 2 || grantTypes[0] != "urn:ietf:params:oauth:grant-type:device_code" || grantTypes[1] != "refresh_token" || !responseOK || len(responseTypes) != 0 {
		http.Error(w, "not a public native client", http.StatusBadRequest)
		return
	}
	f.registeredClient = true
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"client_id":"dynamic-client"}`))
}
func (f *fakeMASServer) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	const scopePrefix = "openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:"
	if !f.registeredClient || r.FormValue("client_id") != "dynamic-client" || !strings.HasPrefix(r.FormValue("scope"), scopePrefix) || strings.TrimPrefix(r.FormValue("scope"), scopePrefix) == "" {
		http.Error(w, "invalid device request", http.StatusBadRequest)
		return
	}
	f.deviceID = strings.TrimPrefix(r.FormValue("scope"), scopePrefix)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"device_code":"device-code","user_code":"ABCD-EFGH","expires_in":60,"interval":1}`))
}
func (f *fakeMASServer) linkGet(w http.ResponseWriter, r *http.Request) {
	if !f.authenticated(r) {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	f.form(w)
}
func (f *fakeMASServer) linkPost(w http.ResponseWriter, r *http.Request) {
	if !f.authenticated(r) || !f.validCSRF(r) || r.FormValue("code") != "ABCD-EFGH" {
		http.Error(w, "bad link", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/device/device-123", http.StatusSeeOther)
}
func (f *fakeMASServer) deviceGet(w http.ResponseWriter, r *http.Request) {
	if !f.authenticated(r) {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	f.form(w)
}
func (f *fakeMASServer) devicePost(w http.ResponseWriter, r *http.Request) {
	if !f.authenticated(r) || !f.validCSRF(r) || r.FormValue("confirm_device") != "on" || r.FormValue("action") != "consent" {
		http.Error(w, "bad consent", http.StatusBadRequest)
		return
	}
	f.approved = true
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("<html><body>device linked</body></html>"))
}
func (f *fakeMASServer) tokenPost(w http.ResponseWriter, r *http.Request) {
	if !f.approved || r.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || r.FormValue("device_code") != "device-code" || r.FormValue("client_id") != "dynamic-client" || r.FormValue("client_secret") != "" {
		http.Error(w, "invalid token request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"access_token":"oauth-access","refresh_token":"oauth-refresh","expires_in":3600}`))
}
func (f *fakeMASServer) whoami(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer oauth-access" {
		http.Error(w, "bad token", http.StatusUnauthorized)
		return
	}
	for username := range f.users {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user_id":"@` + username + `:telecrypt.io","device_id":"` + f.deviceID + `"}`))
		return
	}
	http.Error(w, "no user", http.StatusUnauthorized)
}
func (f *fakeMASServer) other(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "/login") || strings.Contains(r.URL.Path, "/api/admin/") {
		f.fallbackCalls++
	}
	w.Write([]byte("done"))
}

func TestProvisionAgent_FullPublicRegistrationAndDeviceOAuth(t *testing.T) {
	fake := newFakeMASServer()
	srv := fake.server()
	defer srv.Close()
	p, err := NewProvisioner(masreg.NewClient(srv.URL), srv.URL, "telecrypt.io")
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	got, err := p.ProvisionAgent(context.Background())
	if err != nil {
		t.Fatalf("ProvisionAgent: %v", err)
	}
	if got.AccessToken != "oauth-access" || got.RefreshToken != "oauth-refresh" || got.ExpiresIn != 3600 || got.OAuthClientID != "dynamic-client" || got.OAuthTokenEndpoint != srv.URL+"/oauth2/token" {
		t.Fatalf("provision result = %#v", got)
	}
	localpart := strings.TrimSuffix(strings.TrimPrefix(got.MXID, "@"), ":telecrypt.io")
	if fake.users[localpart] != got.Password {
		t.Fatal("MAS registration did not receive the returned generated password")
	}
	if !fake.approved {
		t.Fatal("MAS device consent was not completed through the registration session")
	}
	if fake.fallbackCalls != 0 {
		t.Fatalf("password-login/admin calls = %d, want 0", fake.fallbackCalls)
	}
}

func TestProvisionerValidatesBackendHostAndServerName(t *testing.T) {
	for _, raw := range []string{
		"not a URL",
		"https://backend.example/path",
		"https://backend.example/%2F",
		"https://backend.example/?client=secret",
		"https://user:password@backend.example",
		"http://backend.example",
	} {
		if _, err := NewProvisioner(&fakeMASReg{}, raw, "telecrypt.io"); err == nil {
			t.Fatalf("accepted unsafe backend URL %q", raw)
		}
	}
	if _, err := NewProvisioner(&fakeMASReg{}, "https://backend.example", ""); err == nil {
		t.Fatal("accepted missing server name")
	}
	if _, err := NewProvisioner(&fakeMASReg{}, "http://127.0.0.1:9009", "telecrypt.io"); err != nil {
		t.Fatalf("valid loopback backend URL: %v", err)
	}
	if _, err := NewProvisioner(&fakeMASReg{}, "http://[::1]:9009", "telecrypt.io"); err != nil {
		t.Fatalf("valid IPv6 loopback backend URL: %v", err)
	}
	if _, err := NewProvisioner(&fakeMASReg{}, "https://backend.example:8448", "telecrypt.io"); err != nil {
		t.Fatalf("valid explicit-port backend URL: %v", err)
	}
}

func TestFullFlowRejectsOAuthFailure(t *testing.T) {
	// A device authorization failure is fatal; there is no password-login fallback.
	displayNameDone := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/register" {
			http.Redirect(w, r, "/register/password", http.StatusSeeOther)
			return
		}
		if r.URL.Path == "/register/password" && r.Method == http.MethodGet {
			http.SetCookie(w, &http.Cookie{Name: "csrf", Value: "x", Path: "/"})
			w.Write([]byte(`<input name="csrf" value="x">`))
			return
		}
		if r.URL.Path == "/register/password" {
			http.Redirect(w, r, "/register/steps/a/finish", http.StatusSeeOther)
			return
		}
		if strings.Contains(r.URL.Path, "/finish") {
			if displayNameDone {
				http.Redirect(w, r, "/welcome", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/register/steps/a/display-name", http.StatusSeeOther)
			}
			return
		}
		if strings.Contains(r.URL.Path, "display-name") && r.Method == http.MethodGet {
			http.SetCookie(w, &http.Cookie{Name: "csrf", Value: "x", Path: "/"})
			w.Write([]byte(`<input name="csrf" value="x">`))
			return
		}
		if strings.Contains(r.URL.Path, "display-name") {
			http.SetCookie(w, &http.Cookie{Name: "mas_session", Value: "registered", Path: "/"})
			displayNameDone = true
			http.Redirect(w, r, "/register/steps/a/finish", http.StatusSeeOther)
			return
		}
		if r.URL.Path == "/oauth2/registration" {
			http.Error(w, "DCR disabled", http.StatusForbidden)
			return
		}
		w.Write([]byte("done"))
	}))
	defer srv.Close()
	_, err := masreg.NewClient(srv.URL).RegisterAndAuthorizeDevice(context.Background(), "agent", "password", "DEVICE-12345", srv.URL)
	if err == nil || !strings.Contains(err.Error(), "register public OAuth client") {
		t.Fatalf("error = %v, want DCR failure", err)
	}
}
