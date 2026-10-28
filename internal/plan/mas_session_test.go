package plan

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMASSessionLoginRevocationOutageAndLogoutRetry(t *testing.T) {
	active, outage, failRevoke := true, false, false
	introspections, revocations := 0, 0
	mas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "plan" || pass != "test-secret" || r.Method != http.MethodPost {
			t.Error("ordinary client authentication missing")
		}
		if outage {
			http.Error(w, "MAS unavailable", 503)
			return
		}
		if r.URL.Path == "/oauth2/token" {
			fmt.Fprint(w, `{"access_token":"access","refresh_token":"mas-refresh"}`)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("token") != "mas-refresh" || r.Form.Get("token_type_hint") != "refresh_token" {
			t.Error("incorrect MAS token request")
		}
		switch r.URL.Path {
		case "/oauth2/introspect":
			introspections++
			fmt.Fprintf(w, `{"active":%t,"username":"alice","client_id":"plan","token_type":"refresh_token"}`, active)
		case "/oauth2/revoke":
			revocations++
			if failRevoke {
				http.Error(w, "retry revocation", 503)
				return
			}
			active = false
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer mas.Close()
	srv := testServer()
	srv.oidc = NewOIDCClient(srv.cfg.BackendPublicURL, mas.URL, "plan", "test-secret", srv.cfg.BackendPublicURL+"/plan/callback")
	cashier := &fakeCashier{state: PlanState{Members: []Member{{MXID: "@alice:stage.telecrypt.io"}}}}
	srv.cashier = cashier
	oauth := httptest.NewRecorder()
	setOAuthCookies(oauth, "state", "verifier")
	request := httptest.NewRequest("GET", "/plan/callback?state=state&code=code", nil)
	for _, cookie := range oauth.Result().Cookies() {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != 302 {
		t.Fatalf("login: %d %s", response.Code, response.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range response.Result().Cookies() {
		if c.Name == sessionCookieName {
			cookie = c
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.MaxAge != 7*24*60*60 {
		t.Fatalf("session cookie: %+v", cookie)
	}
	call := func(method, path, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.AddCookie(cookie)
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}
	origin := "https://backend.stage.telecrypt.io"
	if rec := call("POST", "/plan/members/leave", origin); rec.Code != 204 || cashier.removed != "@alice:stage.telecrypt.io" {
		t.Fatalf("authorized action: %d %s", rec.Code, rec.Body.String())
	}
	cashier.removed = ""
	if rec := call("POST", "/plan/members/leave", "https://foreign.test"); rec.Code != 403 || cashier.removed != "" {
		t.Fatalf("cross-origin action: %d", rec.Code)
	}
	if rec := call("POST", "/plan/logout", "https://foreign.test"); rec.Code != 403 || revocations != 0 {
		t.Fatalf("cross-origin logout: %d", rec.Code)
	}
	outage = true
	for _, path := range []string{"/plan/overview", "/plan/members/leave", "/plan/logout"} {
		method := "POST"
		if path == "/plan/overview" {
			method = "GET"
		}
		if rec := call(method, path, origin); rec.Code != 503 || cashier.removed != "" || len(rec.Result().Cookies()) != 0 {
			t.Fatalf("outage %s: %d", path, rec.Code)
		}
	}
	outage = false
	active = false // MAS reports the same inactive result for a revoked session or deactivated user.
	if rec := call("POST", "/plan/members/leave", origin); rec.Code != 401 || cashier.removed != "" {
		t.Fatalf("revoked action: %d", rec.Code)
	}
	if rec := call("GET", "/plan/overview", origin); strings.Contains(rec.Body.String(), "Signed in as") {
		t.Fatal("revoked page retained management access")
	}
	active = true
	failRevoke = true
	if rec := call("POST", "/plan/logout", origin); rec.Code != 503 || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("failed revocation cleared session: %d", rec.Code)
	}
	failRevoke = false
	rec := call("POST", "/plan/logout", origin)
	if rec.Code != 303 || len(rec.Result().Cookies()) != 1 || rec.Result().Cookies()[0].MaxAge != -1 || active {
		t.Fatalf("logout: %d %+v", rec.Code, rec.Result().Cookies())
	}
	if rec := call("POST", "/plan/members/leave", origin); rec.Code != 401 {
		t.Fatalf("replayed revoked cookie: %d", rec.Code)
	}
	if introspections < 8 || revocations != 2 {
		t.Fatalf("MAS calls: %d %d", introspections, revocations)
	}
}

func TestOldTamperedAndExpiredCookiesRequireLogin(t *testing.T) {
	srv := testServer()
	oldPayload := fmt.Sprintf("@alice:stage.telecrypt.io|%d", time.Now().Add(time.Hour).Unix())
	expired := fmt.Sprintf("v2|token|%d", time.Now().Add(-time.Second).Unix())
	for _, value := range []string{
		base64.RawURLEncoding.EncodeToString([]byte(oldPayload + "|" + srv.session.sign(oldPayload))),
		base64.RawURLEncoding.EncodeToString([]byte(expired + "|" + srv.session.sign(expired))),
		"tampered",
	} {
		req := httptest.NewRequest("POST", "/plan/members/leave", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: value})
		req.Header.Set("Origin", "https://backend.stage.telecrypt.io")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Fatalf("invalid cookie authorized: %d", rec.Code)
		}
	}
}
