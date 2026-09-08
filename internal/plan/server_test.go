package plan

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// sharedUIProvenanceJSON is the release record for the vendored shared stylesheet.
//
//go:embed assets/SHARED_UI_PROVENANCE.json
var sharedUIProvenanceJSON []byte

type fakeCashier struct {
	principal Principal
	requestID string
	state     PlanState
	planErr   error
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (f *fakeCashier) PlanState(context.Context, Principal) (PlanState, error) {
	return f.state, f.planErr
}
func (f *fakeCashier) CreatePlan(_ context.Context, p Principal, requestID string) error {
	f.principal, f.requestID = p, requestID
	return nil
}
func (f *fakeCashier) AttachSeat(context.Context, Principal, string, string) error {
	return errors.New("unused")
}
func (f *fakeCashier) RemoveSeat(context.Context, Principal, string, string) error {
	return errors.New("unused")
}
func (f *fakeCashier) StartCheckout(context.Context, Principal, string, int) (string, error) {
	return "", errors.New("unused")
}
func (f *fakeCashier) OpenCustomerPortal(context.Context, Principal, string) (string, error) {
	return "", errors.New("unused")
}
func (f *fakeCashier) ChangeSeatCount(context.Context, Principal, string, int) error {
	return errors.New("unused")
}

func testServer() *Server {
	return NewServer(Config{
		BillingEnvironment: "test",
		ServerName:         "stage.telecrypt.io",
		BackendPublicURL:   "https://backend.stage.telecrypt.io",
		MASInternalURL:     "http://mas:8080",
		PlanPublicURL:      "https://backend.stage.telecrypt.io/plan",
		MASClientID:        "plan",
		MASClientSecret:    "test-secret",
		PlanSessionKey:     "test-session-key",
	}, nil)
}

func TestServerRendersPublicPlanLoginSurface(t *testing.T) {
	srv := testServer()
	req := httptest.NewRequest(http.MethodGet, "/plan", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusOK; got != want {
		t.Fatalf("GET /plan status = %d, want %d", got, want)
	}
	if got, want := rec.Header().Get("Cache-Control"), "no-store"; got != want {
		t.Fatalf("GET /plan Cache-Control = %q, want %q", got, want)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != planContentSecurityPolicy {
		t.Fatalf("GET /plan Content-Security-Policy = %q, want %q", got, planContentSecurityPolicy)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/plan/login") {
		t.Fatal("GET /plan does not offer the MAS login route")
	}
	for _, marker := range []string{
		"Create a TeleCrypt account",
		"/plan/assets/logo-mark.png",
		"/plan/assets/product.css",
		"/plan/assets/plan.css",
		"/plan/assets/plan.js",
		"Sign-in is handled by your TeleCrypt account.",
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("public Plan page is missing %q", marker)
		}
	}
}

func TestServerRendersPersistentSandboxBanner(t *testing.T) {
	srv := testServer()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/plan", nil))
	if !strings.Contains(rec.Body.String(), "TEST / SANDBOX") {
		t.Fatal("GET /plan does not visibly identify the test deployment")
	}
}

func TestPlanLogsPrivateCashierFailureWithoutExposingIt(t *testing.T) {
	const privateDetail = "token=fixture-plan-secret"
	previous := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	srv := testServer()
	srv.cashier = &fakeCashier{planErr: errors.New(privateDetail)}
	req := authenticatedPlanRequest(t, srv, http.MethodGet, "/plan", "")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusServiceUnavailable; got != want {
		t.Fatalf("GET /plan failure status = %d, want %d", got, want)
	}
	if strings.Contains(rec.Body.String(), privateDetail) {
		t.Fatalf("GET /plan exposed private Cashier detail: %q", rec.Body.String())
	}
	if !strings.Contains(logs.String(), "operation=\"load Cashier plan state\"") {
		t.Fatalf("Cashier operation was not logged: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "token=[REDACTED]") || strings.Contains(logs.String(), "fixture-plan-secret") {
		t.Fatalf("Cashier failure was not sanitized in logs: %s", logs.String())
	}
}

func TestValidateLocalpartMatchesMatrixUserLocalpartRules(t *testing.T) {
	for _, tt := range []struct {
		localpart string
		valid     bool
	}{
		{localpart: "alice", valid: true},
		{localpart: "user_name-1.2/3=4", valid: true},
		{localpart: "agent+01", valid: true},
		{localpart: "", valid: false},
		{localpart: "Alice", valid: false},
		{localpart: "alice:remote", valid: false},
		{localpart: "alice@example", valid: false},
	} {
		t.Run(tt.localpart, func(t *testing.T) {
			if got := validateLocalpart(tt.localpart); got != tt.valid {
				t.Fatalf("validateLocalpart(%q) = %t, want %t", tt.localpart, got, tt.valid)
			}
		})
	}
}

func TestCallbackRejectsInvalidProviderUsername(t *testing.T) {
	srv := testServer()
	srv.oidc.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := `{"access_token":"token"}`
		if req.URL.Path != "/oauth2/token" {
			body = `{"username":"invalid:username"}`
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})
	cookies := httptest.NewRecorder()
	setOAuthCookies(cookies, "state", "verifier")
	req := httptest.NewRequest(http.MethodGet, "/plan/callback?state=state&code=code", nil)
	for _, cookie := range cookies.Result().Cookies() {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusBadGateway; got != want {
		t.Fatalf("callback status = %d, want %d", got, want)
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			t.Fatal("callback issued a session for an invalid provider username")
		}
	}
}

func TestCallbackLogsOAuthExchangeFailureWithoutExposingIt(t *testing.T) {
	previous := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	srv := testServer()
	srv.oidc.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("token=fixture-oauth-secret")
	})
	cookies := httptest.NewRecorder()
	setOAuthCookies(cookies, "state", "verifier")
	req := httptest.NewRequest(http.MethodGet, "/plan/callback?state=state&code=code", nil)
	for _, cookie := range cookies.Result().Cookies() {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusBadGateway; got != want {
		t.Fatalf("OAuth exchange failure status = %d, want %d", got, want)
	}
	if strings.Contains(rec.Body.String(), "fixture-oauth-secret") {
		t.Fatalf("OAuth exchange failure exposed private detail: %q", rec.Body.String())
	}
	if !strings.Contains(logs.String(), "operation=\"exchange OAuth code\"") ||
		!strings.Contains(logs.String(), "[REDACTED]") ||
		strings.Contains(logs.String(), "fixture-oauth-secret") {
		t.Fatalf("OAuth exchange failure was not logged safely: %s", logs.String())
	}
}

func TestParseOAuthCallbackRequiresExactParameterContract(t *testing.T) {
	for _, raw := range []string{
		"state=state&code=code&unexpected=value",
		"state=state&state=other&code=code",
		"state=state&code=code&error=access_denied",
		"state=state&code=code&error_description=unexpected",
		"state=state&error_description=missing-error",
		"state=state&error=",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := parseOAuthCallback(httptest.NewRequest(http.MethodGet, "/plan/callback?"+raw, nil)); err == nil {
				t.Fatalf("parseOAuthCallback(%q) accepted an invalid callback", raw)
			}
		})
	}
	params, err := parseOAuthCallback(httptest.NewRequest(http.MethodGet, "/plan/callback?state=state&error=access_denied&error_description=cancelled", nil))
	if err != nil || params.state != "state" || params.providerError != "access_denied" || params.code != "" {
		t.Fatalf("provider-error callback = %#v, %v", params, err)
	}
}

func TestCallbackProviderErrorClearsTransientOAuthCookies(t *testing.T) {
	srv := testServer()
	cookies := httptest.NewRecorder()
	setOAuthCookies(cookies, "state", "verifier")
	req := httptest.NewRequest(http.MethodGet, "/plan/callback?state=state&error=access_denied", nil)
	for _, cookie := range cookies.Result().Cookies() {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("provider-error callback status = %d, want 400", rec.Code)
	}
	setCookie := strings.Join(rec.Header()["Set-Cookie"], "\n")
	for _, name := range []string{oauthStateCookie, oauthPKCECookie, oauthIntentCookie} {
		if !strings.Contains(setCookie, name+"=;") {
			t.Fatalf("provider-error callback did not clear %s: %q", name, setCookie)
		}
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("callback Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("callback Referrer-Policy = %q, want no-referrer", got)
	}
}

func TestCallbackStateMismatchDoesNotClearNewerLoginAttempt(t *testing.T) {
	srv := testServer()
	cookies := httptest.NewRecorder()
	setOAuthCookies(cookies, "new-state", "new-verifier")
	req := httptest.NewRequest(http.MethodGet, "/plan/callback?state=old-state&code=old-code", nil)
	for _, cookie := range cookies.Result().Cookies() {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("stale callback status = %d, want 400", rec.Code)
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == oauthStateCookie || cookie.Name == oauthPKCECookie || cookie.Name == oauthIntentCookie {
			t.Fatalf("stale callback cleared current OAuth cookie %q", cookie.Name)
		}
	}
}

func TestCallbackMalformedMatchingStateClearsTransientOAuthCookies(t *testing.T) {
	srv := testServer()
	cookies := httptest.NewRecorder()
	setOAuthCookies(cookies, "state", "verifier")
	req := httptest.NewRequest(http.MethodGet, "/plan/callback?state=state&code=code&unexpected=value", nil)
	for _, cookie := range cookies.Result().Cookies() {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed callback status = %d, want 400", rec.Code)
	}
	setCookie := strings.Join(rec.Header()["Set-Cookie"], "\n")
	for _, name := range []string{oauthStateCookie, oauthPKCECookie, oauthIntentCookie} {
		if !strings.Contains(setCookie, name+"=;") {
			t.Fatalf("malformed matching callback did not clear %s: %q", name, setCookie)
		}
	}
}

func TestCallbackExpiredIntentConsumesOnlyExpiredOAuthAttempt(t *testing.T) {
	srv := testServer()
	cookies := httptest.NewRecorder()
	setOAuthCookies(cookies, "state", "verifier")
	req := httptest.NewRequest(http.MethodGet, "/plan/callback?state=state&code=code", nil)
	for _, cookie := range cookies.Result().Cookies() {
		if cookie.Name == oauthIntentCookie {
			cookie.Value = strconv.FormatInt(time.Now().Add(-oauthIntentMaxAge-time.Second).Unix(), 10)
		}
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expired callback status = %d, want 400", rec.Code)
	}
	if !strings.Contains(strings.Join(rec.Header()["Set-Cookie"], "\n"), oauthIntentCookie+"=;") {
		t.Fatal("expired callback did not clear expired OAuth intent")
	}
}

func TestCallbackMissingPKCEConsumesMatchingOAuthAttempt(t *testing.T) {
	srv := testServer()
	cookies := httptest.NewRecorder()
	setOAuthCookies(cookies, "state", "verifier")
	req := httptest.NewRequest(http.MethodGet, "/plan/callback?state=state&code=code", nil)
	for _, cookie := range cookies.Result().Cookies() {
		if cookie.Name != oauthPKCECookie {
			req.AddCookie(cookie)
		}
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing-PKCE callback status = %d, want 400", rec.Code)
	}
	setCookie := strings.Join(rec.Header()["Set-Cookie"], "\n")
	for _, name := range []string{oauthStateCookie, oauthPKCECookie, oauthIntentCookie} {
		if !strings.Contains(setCookie, name+"=;") {
			t.Fatalf("missing-PKCE callback did not clear %s", name)
		}
	}
}

func TestOIDCClientRejectsCrossOriginRedirects(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			calls := 0
			client := NewOIDCClient("https://backend.example", "https://mas.example", "client", "secret", "https://plan.example/callback")
			client.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{
					StatusCode: status,
					Header:     http.Header{"Location": {"https://attacker.example/steal"}},
					Body:       io.NopCloser(strings.NewReader("redirect")),
					Request:    r,
				}, nil
			})
			if _, err := client.ExchangeCode(context.Background(), "code", "verifier"); err == nil {
				t.Fatal("ExchangeCode unexpectedly followed redirect")
			}
			if calls != 1 {
				t.Fatalf("transport calls = %d, want 1", calls)
			}
		})
	}
}

func TestOIDCClientDoesNotUseAmbientProxy(t *testing.T) {
	client := NewOIDCClient("https://backend.example", "http://mas:8080", "client", "secret", "https://plan.example/callback")
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("OIDC transport = %T, want *http.Transport", client.httpClient.Transport)
	}
	if transport.Proxy != nil {
		t.Fatalf("OIDC transport proxy is enabled")
	}
}

func TestOIDCClientPreservesResponseCloseFailure(t *testing.T) {
	closeErr := errors.New("OIDC response close failed")
	client := NewOIDCClient("https://backend.example", "https://mas.example", "client", "secret", "https://plan.example/callback")
	client.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       &cashierResponseBody{reader: strings.NewReader(`{"access_token":"access"}`), closeErr: closeErr},
		}, nil
	})
	if _, err := client.ExchangeCode(context.Background(), "code", "verifier"); !errors.Is(err, closeErr) {
		t.Fatalf("OIDC response error = %v, want close failure", err)
	}
}

func TestOIDCClientStatusDiagnosticRetainsSanitizedBody(t *testing.T) {
	const secret = "oidc-client-secret"
	client := NewOIDCClient("https://backend.example", "https://mas.example", "client", secret, "https://plan.example/callback")
	client.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Body:       io.NopCloser(strings.NewReader("provider detail " + secret + " tail")),
		}, nil
	})
	_, err := client.ExchangeCode(context.Background(), "authorization-code", "verifier")
	if err == nil || !strings.Contains(err.Error(), "tail") || strings.Contains(err.Error(), secret) {
		t.Fatalf("OIDC status error = %v, want complete sanitized body", err)
	}
}

func TestPlanAssetsAreLocalAndCarryCommandContract(t *testing.T) {
	srv := testServer()

	for _, asset := range []struct {
		path        string
		contentType string
		marker      string
	}{
		{"/plan/assets/product.css", "text/css; charset=utf-8", "--surface: #ffffff"},
		{"/plan/assets/plan.css", "text/css; charset=utf-8", "Plan-specific layout"},
		{"/plan/assets/plan.js", "text/javascript; charset=utf-8", "X-TeleCrypt-Request-ID"},
		{"/plan/assets/logo-mark.png", "image/png", ""},
	} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, asset.path, nil))
		if got, want := rec.Code, http.StatusOK; got != want {
			t.Errorf("GET %s status = %d, want %d", asset.path, got, want)
		}
		if got, want := rec.Header().Get("Content-Type"), asset.contentType; got != want {
			t.Errorf("GET %s Content-Type = %q, want %q", asset.path, got, want)
		}
		if asset.marker != "" && !strings.Contains(rec.Body.String(), asset.marker) {
			t.Errorf("GET %s is missing %q", asset.path, asset.marker)
		}
	}
}

func TestPlanCustomerPortalWindowPrecedesAsyncSessionRequest(t *testing.T) {
	srv := testServer()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/plan/assets/plan.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("plan JavaScript status = %d", rec.Code)
	}
	source := rec.Body.String()
	open := strings.Index(source, `window.open("about:blank", "_blank")`)
	request := strings.Index(source, `await command("/api/plan/portal"`)
	if open < 0 || request < 0 || open >= request {
		t.Fatal("customer portal window must open synchronously before the session request")
	}
	for _, marker := range []string{
		"portal.opener = null",
		"portal.location.replace(await responseLink(r, \"link\"))",
		"portal.close()",
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("customer portal script is missing %q", marker)
		}
	}
	if strings.Contains(source, "window.open(await responseLink") {
		t.Fatal("customer portal window is still opened after the asynchronous session request")
	}
}

func TestPlanSharedUIAssetMatchesProvenance(t *testing.T) {
	var provenance struct {
		Version          string `json:"version"`
		CanonicalSource  string `json:"canonical_source"`
		CanonicalRelease string `json:"canonical_release"`
		CanonicalCommit  string `json:"canonical_commit"`
		SourceFile       string `json:"source_file"`
		SHA256           string `json:"sha256"`
	}
	if err := json.Unmarshal(sharedUIProvenanceJSON, &provenance); err != nil {
		t.Fatalf("decode shared UI provenance: %v", err)
	}
	if provenance.SourceFile != "src/product.css" {
		t.Fatalf("shared UI provenance source_file = %q, want src/product.css", provenance.SourceFile)
	}
	if provenance.Version != "0.1.8" || provenance.CanonicalRelease != "v0.1.8" {
		t.Fatalf("shared UI provenance release = %q/%q, want 0.1.8/v0.1.8", provenance.Version, provenance.CanonicalRelease)
	}
	if provenance.CanonicalSource != "https://github.com/TeleCrypt-io/ui-shared-css" {
		t.Fatalf("shared UI provenance source = %q, want the canonical shared UI repository", provenance.CanonicalSource)
	}
	if provenance.CanonicalCommit != "257c9ec70024b5d39b76c266c3ab5d129fc34c65" {
		t.Fatalf("shared UI provenance commit = %q, want the v0.1.8 source commit", provenance.CanonicalCommit)
	}
	if len(provenance.SHA256) != sha256.Size*2 {
		t.Fatalf("shared UI provenance sha256 = %q, want a SHA-256 hex digest", provenance.SHA256)
	}
	if _, err := hex.DecodeString(provenance.SHA256); err != nil {
		t.Fatalf("shared UI provenance sha256 = %q is not hexadecimal: %v", provenance.SHA256, err)
	}

	actual := sha256.Sum256(planProductCSS)
	if got := hex.EncodeToString(actual[:]); got != provenance.SHA256 {
		t.Fatalf("vendored product.css sha256 = %q, want provenance %q", got, provenance.SHA256)
	}
}

func TestPlanTemplateHasNoInlineScriptHandlers(t *testing.T) {
	for _, forbidden := range []string{"onclick=", "onsubmit=", "javascript:"} {
		if strings.Contains(strings.ToLower(planHTML), forbidden) {
			t.Fatalf("Plan template contains CSP-incompatible inline script marker %q", forbidden)
		}
	}
}

func TestPlanTemplateCapsSeatQuantity(t *testing.T) {
	if got := strings.Count(planHTML, `max="1000"`); got != 2 {
		t.Fatalf("Plan template has %d seat quantity caps, want 2", got)
	}
}

func TestServerRendersPlanControlsForEachSubscriptionState(t *testing.T) {
	tests := []struct {
		name    string
		plan    *Plan
		seats   []Seat
		want    []string
		notWant []string
	}{
		{
			name:  "checkout",
			plan:  &Plan{SubscriptionStatus: "none", PaidSeats: 1, HasBillingAccount: true},
			seats: []Seat{{MXID: "@member:stage.telecrypt.io"}},
			want: []string{
				"Start sandbox checkout", "15 EUR per seat", "Manage subscription, card, invoices, or cancellation",
				"id=\"add-seat\"", "data-mxid=\"@member:stage.telecrypt.io\"",
			},
		},
		{
			name:    "active subscription",
			plan:    &Plan{SubscriptionStatus: "active", PaidSeats: 3},
			want:    []string{"Update paid seats", "15 EUR per seat", "value=\"3\"", "No seats attached yet."},
			notWant: []string{"Start checkout"},
		},
		{
			name:    "pending checkout",
			plan:    &Plan{SubscriptionStatus: "pending", PaidSeats: 2},
			want:    []string{"Checkout is in progress. Your plan updates after payment is confirmed."},
			notWant: []string{"Start checkout", "Update paid seats"},
		},
		{
			name:    "no plan",
			want:    []string{"Set up your plan", "Set up plan", "Add the Matrix accounts you want covered"},
			notWant: []string{"id=\"add-seat\"", "<h1 id=\"plan-title\">Your Plan</h1>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := renderAuthenticatedPlan(t, PlanState{Plan: tt.plan, Seats: tt.seats})
			for _, marker := range tt.want {
				if !strings.Contains(body, marker) {
					t.Errorf("rendered Plan page is missing %q", marker)
				}
			}
			for _, marker := range tt.notWant {
				if strings.Contains(body, marker) {
					t.Errorf("rendered Plan page unexpectedly contains %q", marker)
				}
			}
		})
	}
}

func renderAuthenticatedPlan(t *testing.T, state PlanState) string {
	t.Helper()
	srv := testServer()
	srv.cashier = &fakeCashier{state: state}
	cookieRecorder := httptest.NewRecorder()
	srv.session.Set(cookieRecorder, "@alice:stage.telecrypt.io")
	cookie := cookieRecorder.Result().Cookies()[0]
	req := httptest.NewRequest(http.MethodGet, "/plan", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)
	if got, want := rec.Code, http.StatusOK; got != want {
		t.Fatalf("GET /plan status = %d, want %d; body: %s", got, want, rec.Body.String())
	}
	return rec.Body.String()
}

func TestPlanCommandsRequireAuthenticatedBrowserSession(t *testing.T) {
	for _, command := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/plan"},
		{http.MethodPost, "/api/plan/seats"},
		{http.MethodDelete, "/api/plan/seats/@member:stage.telecrypt.io"},
		{http.MethodPost, "/api/plan/checkout"},
		{http.MethodPost, "/api/plan/portal"},
		{http.MethodPost, "/api/plan/seat-count"},
	} {
		srv := testServer()
		req := httptest.NewRequest(command.method, command.path, nil)
		req.Header.Set("Origin", "https://backend.stage.telecrypt.io")
		rec := httptest.NewRecorder()

		srv.ServeHTTP(rec, req)

		if got, want := rec.Code, http.StatusUnauthorized; got != want {
			t.Errorf("unauthenticated %s %s status = %d, want %d", command.method, command.path, got, want)
		}
	}
}

func TestPlanRejectsSessionForForeignHomeserver(t *testing.T) {
	srv := testServer()
	cookieRecorder := httptest.NewRecorder()
	srv.session.Set(cookieRecorder, "@alice:other.example")
	req := httptest.NewRequest(http.MethodPost, "/api/plan", nil)
	req.AddCookie(cookieRecorder.Result().Cookies()[0])
	req.Header.Set("Origin", "https://backend.stage.telecrypt.io")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)
	if got, want := rec.Code, http.StatusUnauthorized; got != want {
		t.Fatalf("foreign session status = %d, want %d", got, want)
	}
}

func TestRetiredPlanRoutesAreNotExposed(t *testing.T) {
	for _, path := range []string{"/api/team", "/api/team/seats", "/api/plan/downgrade-request"} {
		rec := httptest.NewRecorder()
		testServer().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if got, want := rec.Code, http.StatusNotFound; got != want {
			t.Errorf("POST %s status = %d, want %d", path, got, want)
		}
	}
}

func TestCreatePlanUsesAuthenticatedPrincipalAndRequestID(t *testing.T) {
	cashier := &fakeCashier{}
	srv := testServer()
	srv.cashier = cashier
	cookieRecorder := httptest.NewRecorder()
	srv.session.Set(cookieRecorder, "@alice:stage.telecrypt.io")
	cookie := cookieRecorder.Result().Cookies()[0]
	requestID := "b3987ed2-51a4-4b04-b5f5-b915683d0cf5"
	req := httptest.NewRequest(http.MethodPost, "/api/plan", nil)
	req.AddCookie(cookie)
	req.Header.Set("Origin", "https://backend.stage.telecrypt.io")
	req.Header.Set("X-TeleCrypt-Request-ID", requestID)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusNoContent; got != want {
		t.Fatalf("POST /api/plan status = %d, want %d", got, want)
	}
	if got, want := cashier.principal.MXID, "@alice:stage.telecrypt.io"; got != want {
		t.Fatalf("Cashier principal = %q, want %q", got, want)
	}
	if got, want := cashier.requestID, requestID; got != want {
		t.Fatalf("Cashier request ID = %q, want %q", got, want)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("POST /api/plan response body = %q, want empty", rec.Body.String())
	}
}

func TestPlanCommandsRejectUnsafeRequestBodies(t *testing.T) {
	for _, tt := range []struct {
		name, path, body string
	}{
		{"unknown field", "/api/plan/seats", `{"mxid":"@member:stage.telecrypt.io","unexpected":true}`},
		{"trailing JSON", "/api/plan/seat-count", `{"quantity":1}{"quantity":2}`},
		{"seat-count quantity above cap", "/api/plan/seat-count", `{"quantity":1001}`},
		{"checkout quantity above cap", "/api/plan/checkout", `{"quantity":1001}`},
		{"oversized JSON", "/api/plan/seats", `{"mxid":"@` + strings.Repeat("a", maxPlanJSONBodyBytes) + `:stage.telecrypt.io"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := testServer()
			srv.cashier = &fakeCashier{}
			req := authenticatedPlanRequest(t, srv, http.MethodPost, tt.path, tt.body)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if got, want := rec.Code, http.StatusBadRequest; got != want {
				t.Fatalf("%s status = %d, want %d", tt.path, got, want)
			}
		})
	}
}

func TestDeleteSeatRejectsNonLocalMXID(t *testing.T) {
	srv := testServer()
	srv.cashier = &fakeCashier{}
	req := authenticatedPlanRequest(t, srv, http.MethodDelete, "/api/plan/seats/@member:elsewhere.test", "")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if got, want := rec.Code, http.StatusBadRequest; got != want {
		t.Fatalf("DELETE remote MXID status = %d, want %d", got, want)
	}
}

// errorCashier returns a CashierError carrying a provider response. Plan must rewrite only its
// narrowly defined local capacity message and keep every other body private.
type errorCashier struct {
	status  int
	message string
}

func (c *errorCashier) PlanState(_ context.Context, _ Principal) (PlanState, error) {
	return PlanState{}, &CashierError{StatusCode: c.status, Message: c.message}
}
func (c *errorCashier) CreatePlan(_ context.Context, _ Principal, _ string) error {
	return &CashierError{StatusCode: c.status, Message: c.message}
}
func (c *errorCashier) AttachSeat(_ context.Context, _ Principal, _ string, _ string) error {
	return &CashierError{StatusCode: c.status, Message: c.message}
}
func (c *errorCashier) RemoveSeat(_ context.Context, _ Principal, _ string, _ string) error {
	return &CashierError{StatusCode: c.status, Message: c.message}
}
func (c *errorCashier) StartCheckout(_ context.Context, _ Principal, _ string, _ int) (string, error) {
	return "", &CashierError{StatusCode: c.status, Message: c.message}
}
func (c *errorCashier) OpenCustomerPortal(_ context.Context, _ Principal, _ string) (string, error) {
	return "", &CashierError{StatusCode: c.status, Message: c.message}
}
func (c *errorCashier) ChangeSeatCount(_ context.Context, _ Principal, _ string, _ int) error {
	return &CashierError{StatusCode: c.status, Message: c.message}
}

func TestCashierCapacityRejectionIsRewrittenLocally(t *testing.T) {
	const message = "remove 1 seat(s) before lowering to 1 paid seats"
	const wantMessage = "Remove 1 seat(s) before lowering to 1 paid seats."
	for _, tt := range []struct {
		name, method, path, body string
	}{
		{"seat-count", http.MethodPost, "/api/plan/seat-count", `{"quantity":1}`},
		{"attach", http.MethodPost, "/api/plan/seats", `{"mxid":"@bot:stage.telecrypt.io"}`},
		{"remove", http.MethodDelete, "/api/plan/seats/@bot:stage.telecrypt.io", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := testServer()
			srv.cashier = &errorCashier{status: http.StatusConflict, message: message}
			req := authenticatedPlanRequest(t, srv, tt.method, tt.path, tt.body)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if got, want := rec.Code, http.StatusConflict; got != want {
				t.Fatalf("%s status = %d, want %d", tt.name, got, want)
			}
			if got := strings.TrimSpace(rec.Body.String()); got != wantMessage {
				t.Fatalf("%s body = %q, want %q", tt.name, got, wantMessage)
			}
		})
	}
}

func TestCashierArbitraryErrorBodyIsNeverForwarded(t *testing.T) {
	const secret = "database password=super-secret"
	for _, tt := range []struct {
		name, method, path, body string
	}{
		{"seat-count", http.MethodPost, "/api/plan/seat-count", `{"quantity":1}`},
		{"attach", http.MethodPost, "/api/plan/seats", `{"mxid":"@bot:stage.telecrypt.io"}`},
		{"remove", http.MethodDelete, "/api/plan/seats/@bot:stage.telecrypt.io", ""},
		{"create", http.MethodPost, "/api/plan", ""},
		{"checkout", http.MethodPost, "/api/plan/checkout", `{"quantity":1}`},
		{"portal", http.MethodPost, "/api/plan/portal", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := testServer()
			srv.cashier = &errorCashier{status: http.StatusConflict, message: secret}
			req := authenticatedPlanRequest(t, srv, tt.method, tt.path, tt.body)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if got, want := rec.Code, http.StatusBadGateway; got != want {
				t.Fatalf("%s status = %d, want %d", tt.name, got, want)
			}
			if strings.Contains(rec.Body.String(), secret) {
				t.Fatalf("%s forwarded private Cashier body: %q", tt.name, rec.Body.String())
			}
		})
	}
}

type planWriteFailureResponseWriter struct {
	header http.Header
	err    error
}

func (w *planWriteFailureResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *planWriteFailureResponseWriter) WriteHeader(int) {}

func (w *planWriteFailureResponseWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestPlanWriteJSONLogsResponseWriteFailure(t *testing.T) {
	previous := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	writeJSON(&planWriteFailureResponseWriter{err: errors.New("fixture Plan client disconnected")}, http.StatusOK, map[string]string{"status": "ok"})

	if !strings.Contains(logs.String(), "operation=\"write JSON response\"") {
		t.Fatalf("response write failure was not logged: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "fixture Plan client disconnected") {
		t.Fatalf("response write failure detail was not logged: %s", logs.String())
	}
}

func TestCashierLinkAllowLists(t *testing.T) {
	for _, tc := range []struct {
		name               string
		billingEnvironment string
		link               string
		want               bool
	}{
		{name: "production checkout valid", billingEnvironment: "live", link: "https://checkout.dodopayments.com/session/abc123", want: true},
		{name: "sandbox checkout valid", billingEnvironment: "test", link: "https://test.checkout.dodopayments.com/session/abc123", want: true},
		{name: "sandbox rejects live checkout", billingEnvironment: "test", link: "https://checkout.dodopayments.com/session/abc123"},
		{name: "production rejects sandbox checkout", billingEnvironment: "live", link: "https://test.checkout.dodopayments.com/session/abc123"},
		{name: "checkout wrong origin", billingEnvironment: "live", link: "https://attacker.example/session/abc123"},
		{name: "checkout query", billingEnvironment: "live", link: "https://checkout.dodopayments.com/session/abc123?next=https://attacker.example"},
		{name: "checkout extra path", billingEnvironment: "live", link: "https://checkout.dodopayments.com/session/abc/def"},
		{name: "checkout empty session", billingEnvironment: "live", link: "https://checkout.dodopayments.com/session/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validCheckoutLink(tc.link, tc.billingEnvironment); got != tc.want {
				t.Fatalf("validCheckoutLink(%q) = %v, want %v", tc.link, got, tc.want)
			}
		})
	}

	production := testServer()
	production.cfg.ServerName = "telecrypt.io"
	production.cfg.BillingEnvironment = "live"
	for _, tc := range []struct {
		name string
		link string
		want bool
	}{
		{name: "production valid", link: "https://customer.dodopayments.com/portal/abc", want: true},
		{name: "production test host", link: "https://test.customer.dodopayments.com/portal/abc"},
		{name: "production query", link: "https://customer.dodopayments.com/portal/abc?x=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := production.validPortalLink(tc.link); got != tc.want {
				t.Fatalf("validPortalLink(%q) = %v, want %v", tc.link, got, tc.want)
			}
		})
	}
}

func TestValidateLocalMXIDBoundsMatrixIdentity(t *testing.T) {
	serverName := "stage.telecrypt.io"
	valid := "@" + strings.Repeat("a", 220) + ":" + serverName
	if !validateLocalMXID(valid, serverName) {
		t.Fatal("validateLocalMXID rejected a bounded Matrix identity")
	}
	if validateLocalMXID("@"+strings.Repeat("a", 240)+":"+serverName, serverName) {
		t.Fatal("validateLocalMXID accepted an oversized Matrix identity")
	}
	if !validateLocalMXID("@agent+01:"+serverName, serverName) {
		t.Fatal("validateLocalMXID rejected canonical plus localpart")
	}
	if validateLocalMXID("@agent+01:other.example", serverName) {
		t.Fatal("validateLocalMXID accepted a foreign server")
	}
}

func authenticatedPlanRequest(t *testing.T, srv *Server, method, path, body string) *http.Request {
	t.Helper()
	cookieRecorder := httptest.NewRecorder()
	srv.session.Set(cookieRecorder, "@alice:stage.telecrypt.io")
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.AddCookie(cookieRecorder.Result().Cookies()[0])
	req.Header.Set("Origin", "https://backend.stage.telecrypt.io")
	req.Header.Set("X-TeleCrypt-Request-ID", "b3987ed2-51a4-4b04-b5f5-b915683d0cf5")
	return req
}
