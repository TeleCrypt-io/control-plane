package plan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fakeCashier struct {
	principal Principal
	removed   string
	state     PlanState
	planErr   error
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (f *fakeCashier) PlanState(_ context.Context, p Principal) (PlanState, error) {
	f.principal = p
	return f.state, f.planErr
}
func (f *fakeCashier) AttachMember(context.Context, Principal, string) error {
	return errors.New("unused")
}
func (f *fakeCashier) RemoveMember(_ context.Context, p Principal, mxid string) error {
	f.principal, f.removed = p, mxid
	return nil
}
func (f *fakeCashier) LeaveMember(_ context.Context, p Principal) error {
	f.principal, f.removed = p, p.MXID
	return nil
}
func testServer() *Server {
	return NewServer(Config{
		BillingEnvironment: "test",
		ServerName:         "stage.telecrypt.io",
		BackendPublicURL:   "https://backend.stage.telecrypt.io",
		MASInternalURL:     "http://127.0.0.1:8082",
		PlanPublicURL:      "https://backend.stage.telecrypt.io/plan/overview",
		MASClientID:        "plan",
		MASClientSecret:    "test-secret",
		PlanSessionKey:     "test-session-key",
		BillingLinks: []BillingLink{
			{TierID: 1, DisplayName: "Team", URL: "https://checkout.example/team"},
			{TierID: 2, DisplayName: "Business", URL: "https://checkout.example/business"},
		},
		BillingPortalURL: "https://billing.example/portal",
	}, nil)
}

func TestServerUsesPlanCallbackOutsideOverviewURL(t *testing.T) {
	srv := testServer()
	authorizeURL, err := url.Parse(srv.oidc.AuthorizeURL("state", "challenge"))
	if err != nil {
		t.Fatalf("AuthorizeURL: %v", err)
	}
	if got, want := authorizeURL.Query().Get("redirect_uri"), "https://backend.stage.telecrypt.io/plan/callback"; got != want {
		t.Fatalf("OIDC redirect_uri = %q, want %q", got, want)
	}
}

func TestServerRendersPublicPlanLoginSurface(t *testing.T) {
	srv := testServer()
	req := httptest.NewRequest(http.MethodGet, "/plan/overview", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusOK; got != want {
		t.Fatalf("GET /plan/overview status = %d, want %d", got, want)
	}
	if got, want := rec.Header().Get("Cache-Control"), "no-store"; got != want {
		t.Fatalf("GET /plan/overview Cache-Control = %q, want %q", got, want)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != planContentSecurityPolicy {
		t.Fatalf("GET /plan/overview Content-Security-Policy = %q, want %q", got, planContentSecurityPolicy)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/plan/login") {
		t.Fatal("GET /plan/overview does not offer the MAS login route")
	}
	for _, marker := range []string{
		"Create a TeleCrypt account",
		"https://www.telecrypt.io/logo-mark.png",
		"https://www.telecrypt.io/favicon-32x32.png",
		"https://www.telecrypt.io/ui/product.css",
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
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/plan/overview", nil))
	if !strings.Contains(rec.Body.String(), "TEST / SANDBOX") {
		t.Fatal("GET /plan/overview does not visibly identify the test deployment")
	}
}

func TestPlanLogsRawCashierFailureAndKeepsResponseGeneric(t *testing.T) {
	const privateDetail = "token=fixture-plan-secret"
	previous := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	srv := testServer()
	srv.cashier = &fakeCashier{planErr: errors.New(privateDetail)}
	req := authenticatedPlanRequest(t, srv, http.MethodGet, "/plan/overview", "")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusServiceUnavailable; got != want {
		t.Fatalf("GET /plan/overview failure status = %d, want %d", got, want)
	}
	if strings.Contains(rec.Body.String(), privateDetail) {
		t.Fatalf("GET /plan/overview exposed private Cashier detail: %q", rec.Body.String())
	}
	if !strings.Contains(logs.String(), "operation=\"load Cashier plan state\"") {
		t.Fatalf("Cashier operation was not logged: %s", logs.String())
	}
	if !strings.Contains(logs.String(), privateDetail) {
		t.Fatalf("Cashier log omitted complete raw diagnostic: %s", logs.String())
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

func TestCallbackLogsRawOAuthExchangeFailureAndKeepsResponseGeneric(t *testing.T) {
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
		!strings.Contains(logs.String(), "token=fixture-oauth-secret") {
		t.Fatalf("OAuth exchange log omitted complete raw diagnostic: %s", logs.String())
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
	client := NewOIDCClient("https://backend.example", "http://127.0.0.1:8082", "client", "secret", "https://plan.example/callback")
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

func TestOIDCClientStatusDiagnosticRetainsRawBody(t *testing.T) {
	const secret = "oidc-client-secret"
	client := NewOIDCClient("https://backend.example", "https://mas.example", "client", secret, "https://plan.example/callback")
	client.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Body:       io.NopCloser(strings.NewReader("provider detail " + secret + " tail")),
		}, nil
	})
	_, err := client.ExchangeCode(context.Background(), "authorization-code", "verifier")
	if err == nil || !strings.Contains(err.Error(), "provider detail "+secret+" tail") {
		t.Fatalf("OIDC status error = %v, want complete raw body", err)
	}
}

func TestPlanApplicationAssetsAreServedLocally(t *testing.T) {
	srv := testServer()

	for _, asset := range []struct {
		path        string
		contentType string
	}{
		{"/plan/assets/plan.css", "text/css; charset=utf-8"},
		{"/plan/assets/plan.js", "text/javascript; charset=utf-8"},
	} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, asset.path, nil))
		if got, want := rec.Code, http.StatusOK; got != want {
			t.Errorf("GET %s status = %d, want %d", asset.path, got, want)
		}
		if got, want := rec.Header().Get("Content-Type"), asset.contentType; got != want {
			t.Errorf("GET %s Content-Type = %q, want %q", asset.path, got, want)
		}
	}
}

func TestPlanSharedAssetsAreHostedByWebsite(t *testing.T) {
	srv := testServer()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/plan/overview", nil))
	body := rec.Body.String()
	for _, marker := range []string{
		`rel="icon" href="https://www.telecrypt.io/favicon-32x32.png" type="image/png"`,
		`rel="stylesheet" href="https://www.telecrypt.io/ui/product.css"`,
		`class="tc-brand-mark" src="https://www.telecrypt.io/logo-mark.png"`,
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("Plan page is missing shared website asset reference %q", marker)
		}
	}
	for _, localPath := range []string{"/plan/assets/product.css", "/plan/assets/logo-mark.png"} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, localPath, nil))
		if got, want := rec.Code, http.StatusNotFound; got != want {
			t.Errorf("GET %s status = %d, want %d", localPath, got, want)
		}
	}
}

func TestServerRendersPlanControlsForEachSubscriptionState(t *testing.T) {
	tests := []struct {
		name    string
		plan    *Plan
		members []Member
		want    []string
		notWant []string
	}{
		{
			name:    "fixed plan",
			plan:    &Plan{SubscriptionStatus: "active", DisplayName: "Team", MonthlyCents: 1500, MemberLimit: 3},
			members: []Member{{MXID: "@member:stage.telecrypt.io"}},
			want: []string{
				"Team", "Business", "Open billing portal",
				"id=\"add-member\"", "data-mxid=\"@member:stage.telecrypt.io\"",
			},
			notWant: []string{"id=\"checkout\"", "id=\"seat-count\"", "Set up plan", "quantity"},
		},
		{
			name:    "no plan",
			want:    []string{"Choose your plan", "Team", "Business", "Open billing portal"},
			notWant: []string{"Set up plan", "id=\"checkout\"", "quantity", "<h1 id=\"plan-title\">Your Plan</h1>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := renderAuthenticatedPlan(t, PlanState{Plan: tt.plan, Members: tt.members})
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

func TestServerRendersStablePlanStateAndLimits(t *testing.T) {
	body := renderAuthenticatedPlan(t, PlanState{Plan: &Plan{
		DisplayName:  "Team",
		MonthlyCents: 2500,
		StorageBytes: 5_000_000_000,
		UsageBytes:   1_000_000_000,
		MemberLimit:  3,
	}})
	for _, marker := range []string{"Team", "€25.00/month", "5 GB", "1 GB of 5 GB", "Member limit"} {
		if !strings.Contains(body, marker) {
			t.Errorf("rendered Plan page is missing %q", marker)
		}
	}
}

func renderAuthenticatedPlan(t *testing.T, state PlanState) string {
	t.Helper()
	srv := testServer()
	srv.cashier = &fakeCashier{state: state}
	cookieRecorder := httptest.NewRecorder()
	srv.session.Set(cookieRecorder, "@alice:stage.telecrypt.io")
	cookie := cookieRecorder.Result().Cookies()[0]
	req := httptest.NewRequest(http.MethodGet, "/plan/overview", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)
	if got, want := rec.Code, http.StatusOK; got != want {
		t.Fatalf("GET /plan/overview status = %d, want %d; body: %s", got, want, rec.Body.String())
	}
	return rec.Body.String()
}

func TestPlanCommandsRequireAuthenticatedBrowserSession(t *testing.T) {
	for _, command := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/plan/members/add"},
		{http.MethodPost, "/plan/members/leave"},
		{http.MethodPost, "/plan/members/@member:stage.telecrypt.io/remove"},
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
	req := httptest.NewRequest(http.MethodPost, "/plan/members/add", nil)
	req.AddCookie(cookieRecorder.Result().Cookies()[0])
	req.Header.Set("Origin", "https://backend.stage.telecrypt.io")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)
	if got, want := rec.Code, http.StatusUnauthorized; got != want {
		t.Fatalf("foreign session status = %d, want %d", got, want)
	}
}

func TestMemberCanLeaveOnlyWhenCashierShowsTheirMembership(t *testing.T) {
	cashier := &fakeCashier{state: PlanState{Members: []Member{{MXID: "@alice:stage.telecrypt.io"}}}}
	srv := testServer()
	srv.cashier = cashier
	req := authenticatedPlanRequest(t, srv, http.MethodPost, "/plan/members/leave", "")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if got, want := rec.Code, http.StatusNoContent; got != want {
		t.Fatalf("member leave status = %d, want %d", got, want)
	}
	if cashier.removed != "@alice:stage.telecrypt.io" {
		t.Fatalf("Cashier removal target = %q, want caller", cashier.removed)
	}

}

func TestRetiredPlanRoutesAreNotExposed(t *testing.T) {
	for _, path := range []string{"/api/team", "/api/team/seats", "/plan", "/plan/", "/plan/api", "/plan/api/seats", "/plan/api/checkout", "/plan/api/portal", "/plan/api/seat-count", "/plan/api/downgrade-request", "/plan/create", "/plan/checkout/start", "/plan/billing-portal/open", "/plan/seats/update"} {
		rec := httptest.NewRecorder()
		testServer().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if got, want := rec.Code, http.StatusNotFound; got != want {
			t.Errorf("POST %s status = %d, want %d", path, got, want)
		}
	}
}

func TestPlanCommandsRejectUnsafeRequestBodies(t *testing.T) {
	for _, tt := range []struct {
		name, path, body string
	}{
		{"unknown field", "/plan/members/add", `{"mxid":"@member:stage.telecrypt.io","unexpected":true}`},
		{"trailing JSON", "/plan/members/add", `{"mxid":"@member:stage.telecrypt.io"}{"mxid":"@other:stage.telecrypt.io"}`},
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
	req := authenticatedPlanRequest(t, srv, http.MethodPost, "/plan/members/@member:elsewhere.test/remove", "")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if got, want := rec.Code, http.StatusBadRequest; got != want {
		t.Fatalf("POST remote MXID status = %d, want %d", got, want)
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
func (c *errorCashier) AttachMember(_ context.Context, _ Principal, _ string) error {
	return &CashierError{StatusCode: c.status, Message: c.message}
}
func (c *errorCashier) RemoveMember(_ context.Context, _ Principal, _ string) error {
	return &CashierError{StatusCode: c.status, Message: c.message}
}
func (c *errorCashier) LeaveMember(_ context.Context, _ Principal) error {
	return &CashierError{StatusCode: c.status, Message: c.message}
}

func TestCashierArbitraryErrorBodyIsNeverForwarded(t *testing.T) {
	const secret = "database password=super-secret"
	for _, tt := range []struct {
		name, method, path, body string
	}{
		{"attach", http.MethodPost, "/plan/members/add", `{"mxid":"@bot:stage.telecrypt.io"}`},
		{"remove", http.MethodPost, "/plan/members/@bot:stage.telecrypt.io/remove", ""},
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
	return req
}

func TestSponsorAccessRoutesAreNotExposed(t *testing.T) {
	for _, path := range []string{
		"/plan/members/@member:stage.telecrypt.io/lock",
		"/plan/members/@member:stage.telecrypt.io/unlock",
	} {
		rec := httptest.NewRecorder()
		testServer().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if got, want := rec.Code, http.StatusNotFound; got != want {
			t.Errorf("POST %s status = %d, want %d", path, got, want)
		}
	}
}

// Probing health must not create an account or call billing services.
func TestHealth(t *testing.T) {
	srv := testServer()
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", response.Code)
	}
}
