package plan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// Config is Plan's browser-facing configuration. It deliberately excludes every Dodo,
// Synapse-admin, and database setting.
type Config struct {
	BillingEnvironment string
	ServerName         string
	BackendPublicURL   string
	MASInternalURL     string
	PlanPublicURL      string
	MASClientID        string
	MASClientSecret    string
	PlanSessionKey     string
	BillingLinks       []BillingLink
	BillingPortalURL   string
}

var errCashierUnavailable = errors.New("cashier client is not configured")

const (
	planContentSecurityPolicy = "default-src 'self'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' https://www.telecrypt.io; object-src 'none'; script-src 'self'; style-src 'self' https://www.telecrypt.io"
)

// Server owns all public Plan routes. Cashier provides billing and team ownership.
type Server struct {
	cfg     Config
	cashier CashierClient
	oidc    *OIDCClient
	session *Session
	mux     *http.ServeMux
}

func NewServer(cfg Config, cashier CashierClient) *Server {
	s := &Server{cfg: cfg, cashier: cashier, session: NewSession(cfg.PlanSessionKey, cfg.ServerName), mux: http.NewServeMux()}
	s.oidc = NewOIDCClient(cfg.BackendPublicURL, cfg.MASInternalURL, cfg.MASClientID, cfg.MASClientSecret, strings.TrimRight(cfg.BackendPublicURL, "/")+"/plan/callback")
	s.mux.HandleFunc("GET /plan/overview", s.handlePlan)
	s.mux.HandleFunc("GET /plan/assets/plan.css", s.handlePlanCSS)
	s.mux.HandleFunc("GET /plan/assets/plan.js", s.handlePlanJS)
	s.mux.HandleFunc("GET /plan/login", s.handleLogin)
	s.mux.HandleFunc("GET /plan/callback", s.handleCallback)
	s.mux.Handle("POST /plan/members/add", s.requireBrowserSession(http.HandlerFunc(s.handleAddMember)))
	s.mux.Handle("POST /plan/members/leave", s.requireBrowserSession(http.HandlerFunc(s.handleLeaveTeam)))
	s.mux.Handle("POST /plan/members/{mxid}/remove", s.requireBrowserSession(http.HandlerFunc(s.handleRemoveMember)))
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", planContentSecurityPolicy)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) requireBrowserSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mxid, err := s.session.MXID(r)
		if err != nil {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		if !s.isPlanOrigin(r.Header.Get("Origin")) {
			http.Error(w, "invalid request origin", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalContextKey{}, Principal{MXID: mxid})))
	})
}

func (s *Server) isPlanOrigin(origin string) bool {
	if origin == "" || origin == "null" {
		return false
	}
	planURL, err := url.Parse(s.cfg.PlanPublicURL)
	if err != nil || planURL.Scheme == "" || planURL.Host == "" {
		return false
	}
	originURL, err := url.Parse(origin)
	if err != nil || originURL.Scheme == "" || originURL.Host == "" || originURL.Path != "" || originURL.RawQuery != "" || originURL.Fragment != "" || originURL.User != nil {
		return false
	}
	return originURL.Scheme == planURL.Scheme && originURL.Host == planURL.Host
}

type principalContextKey struct{}

func principalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(Principal)
	return p, ok
}

func (s *Server) client() (CashierClient, error) {
	if s.cashier == nil {
		return nil, errCashierUnavailable
	}
	return s.cashier, nil
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	mxid, err := s.session.MXID(r)
	data := pageData{
		LoggedIn:         err == nil,
		TestMode:         s.cfg.BillingEnvironment == "test",
		MXID:             mxid,
		RegisterURL:      strings.TrimRight(s.cfg.BackendPublicURL, "/") + "/register",
		BillingLinks:     billingLinksForPrincipal(s.cfg.BillingLinks, mxid),
		BillingPortalURL: s.cfg.BillingPortalURL,
	}
	if data.LoggedIn {
		client, err := s.client()
		if err != nil {
			logPlanFailure("load Cashier client for plan view", err)
			http.Error(w, "Plan is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		state, err := client.PlanState(r.Context(), Principal{MXID: mxid})
		if err != nil {
			logPlanFailure("load Cashier plan state", err)
			http.Error(w, "Plan is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		data.Plan, data.Members = state.Plan, state.Members
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := planTmpl.Execute(w, data); err != nil {
		logPlanFailure("render plan page", err)
		http.Error(w, "Plan is temporarily unavailable", http.StatusInternalServerError)
	}
}

func (s *Server) handlePlanCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(planCSS); err != nil {
		logPlanFailure("write plan stylesheet", err)
	}
}

func (s *Server) handlePlanJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(planJS); err != nil {
		logPlanFailure("write plan JavaScript", err)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	verifier, challenge, err := NewPKCEPair()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state := uuid.NewString()
	setOAuthCookies(w, state, verifier)
	http.Redirect(w, r, s.oidc.AuthorizeURL(state, challenge), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	params, err := parseOAuthCallback(r)
	if err != nil {
		if callbackMatchesOAuthState(r) {
			clearOAuthCookies(w)
		}
		http.Error(w, "invalid oauth callback", http.StatusBadRequest)
		return
	}
	state, err := readOAuthCookie(r, oauthStateCookie)
	if err != nil || params.state != state {
		http.Error(w, "invalid oauth state", http.StatusBadRequest)
		return
	}
	// Do not let a stale or malformed callback from another tab erase a newer login attempt.
	// Once the callback proves ownership of the current state cookie, all later failures consume
	// that attempt's transient state.
	defer clearOAuthCookies(w)
	if err := readOAuthIntent(r); err != nil {
		http.Error(w, "invalid oauth session", http.StatusBadRequest)
		return
	}
	if params.providerError != "" {
		http.Error(w, "oauth authorization was not completed", http.StatusBadRequest)
		return
	}
	verifier, err := readOAuthCookie(r, oauthPKCECookie)
	if err != nil {
		http.Error(w, "invalid oauth session", http.StatusBadRequest)
		return
	}
	token, err := s.oidc.ExchangeCode(r.Context(), params.code, verifier)
	if err != nil {
		logPlanFailure("exchange OAuth code", err)
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	username, err := s.oidc.Username(r.Context(), token)
	if err != nil {
		logPlanFailure("load OAuth username", err)
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	if !validateLocalpart(username) {
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	s.session.Set(w, fmt.Sprintf("@%s:%s", username, s.cfg.ServerName))
	http.Redirect(w, r, s.cfg.PlanPublicURL, http.StatusFound)
}

// callbackMatchesOAuthState proves ownership before consuming transient cookies on a malformed
// callback. A stale callback from another tab must not erase the newer tab's attempt.
func callbackMatchesOAuthState(r *http.Request) bool {
	current, err := readOAuthCookie(r, oauthStateCookie)
	if err != nil {
		return false
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return false
	}
	entries := values["state"]
	return len(entries) == 1 && entries[0] != "" && entries[0] == current
}

type oauthCallbackParams struct {
	state         string
	code          string
	providerError string
}

func parseOAuthCallback(r *http.Request) (oauthCallbackParams, error) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return oauthCallbackParams{}, err
	}
	allowed := map[string]bool{
		"code": true, "state": true, "error": true, "error_description": true, "error_uri": true,
	}
	for name, entries := range values {
		if !allowed[name] || len(entries) != 1 {
			return oauthCallbackParams{}, errors.New("invalid oauth callback parameters")
		}
		if name != "error_description" && name != "error_uri" && !validOAuthCallbackToken(entries[0]) {
			return oauthCallbackParams{}, errors.New("invalid oauth callback parameter value")
		}
	}
	state, ok := singleOAuthParam(values, "state")
	if !ok || state == "" {
		return oauthCallbackParams{}, errors.New("oauth callback has no unique state")
	}
	providerError, hasError := singleOAuthParam(values, "error")
	if hasError {
		if providerError == "" {
			return oauthCallbackParams{}, errors.New("oauth callback has an empty error")
		}
		if _, hasCode := values["code"]; hasCode {
			return oauthCallbackParams{}, errors.New("oauth callback has both code and error")
		}
		return oauthCallbackParams{state: state, providerError: providerError}, nil
	}
	code, ok := singleOAuthParam(values, "code")
	if !ok || code == "" {
		return oauthCallbackParams{}, errors.New("oauth callback has no unique code")
	}
	if _, present := values["error_description"]; present {
		return oauthCallbackParams{}, errors.New("oauth callback error fields require error")
	}
	if _, present := values["error_uri"]; present {
		return oauthCallbackParams{}, errors.New("oauth callback error fields require error")
	}
	return oauthCallbackParams{state: state, code: code}, nil
}

func validOAuthCallbackToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func singleOAuthParam(values url.Values, name string) (string, bool) {
	entries, ok := values[name]
	if !ok || len(entries) != 1 {
		return "", false
	}
	return entries[0], true
}

func (s *Server) command(r *http.Request) (CashierClient, Principal, string, bool) {
	client, err := s.client()
	if err != nil {
		logPlanFailure("load Cashier client for command", err)
		return nil, Principal{}, "", false
	}
	p, ok := principalFromContext(r.Context())
	if !ok {
		return nil, Principal{}, "", false
	}
	requestID := r.Header.Get("X-TeleCrypt-Request-ID")
	if _, err := uuid.Parse(requestID); err != nil {
		return nil, Principal{}, "", false
	}
	return client, p, requestID, true
}
func commandUnavailable(w http.ResponseWriter) {
	http.Error(w, "Plan is temporarily unavailable", http.StatusServiceUnavailable)
}

type memberRequest struct {
	MXID string `json:"mxid"`
}

var matrixLocalpart = regexp.MustCompile(`^[0-9a-z=_+\-./]+$`)

const maxMatrixIDBytes = 255

func validateLocalpart(localpart string) bool {
	return matrixLocalpart.MatchString(localpart)
}

func validateLocalMXID(mxid, serverName string) bool {
	if len(mxid) == 0 || len(mxid) > maxMatrixIDBytes || !strings.HasPrefix(mxid, "@") || serverName == "" {
		return false
	}
	parts := strings.SplitN(strings.TrimPrefix(mxid, "@"), ":", 2)
	return len(parts) == 2 && parts[1] == serverName && validateLocalpart(parts[0])
}
func (s *Server) handleAddMember(w http.ResponseWriter, r *http.Request) {
	client, p, id, ok := s.command(r)
	if !ok {
		commandUnavailable(w)
		return
	}
	var req memberRequest
	if err := decodePlanJSON(w, r, &req); err != nil || !validateLocalMXID(req.MXID, s.cfg.ServerName) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := client.AttachMember(r.Context(), p, id, req.MXID); err != nil {
		writeCashierActionError(w, err, "could not attach member")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	client, p, id, ok := s.command(r)
	if !ok {
		commandUnavailable(w)
		return
	}
	mxid := r.PathValue("mxid")
	if !validateLocalMXID(mxid, s.cfg.ServerName) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := client.RemoveMember(r.Context(), p, id, mxid); err != nil {
		writeCashierActionError(w, err, "could not remove member")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleLeaveTeam lets an attached member request removal of their own membership. Cashier
// verifies membership, enforces the billing-owner rule, and applies the lifecycle transition.
func (s *Server) handleLeaveTeam(w http.ResponseWriter, r *http.Request) {
	client, p, id, ok := s.command(r)
	if !ok {
		commandUnavailable(w)
		return
	}
	if err := client.LeaveMember(r.Context(), p, id); err != nil {
		writeCashierActionError(w, err, "could not leave team")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodePlanJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

// writeCashierActionError keeps private Cashier response bodies at the Plan boundary.
func writeCashierActionError(w http.ResponseWriter, err error, fallback string) {
	logPlanFailure("Cashier action", err)
	http.Error(w, fallback, http.StatusBadGateway)
}
func logPlanFailure(operation string, err error) {
	if err == nil {
		return
	}
	slog.Error("plan operation failed", "operation", operation, "detail", err.Error())
}

type pageData struct {
	LoggedIn, TestMode bool
	MXID, RegisterURL  string
	Plan               *Plan
	Members            []Member
	BillingLinks       []BillingLink
	BillingPortalURL   string
}

// billingLinksForPrincipal keeps checkout links static while carrying the
// authenticated sponsor identity as Dodo metadata. Cashier learns ownership
// only from the signed webhook that returns that metadata.
func billingLinksForPrincipal(links []BillingLink, mxid string) []BillingLink {
	result := append([]BillingLink(nil), links...)
	if mxid == "" {
		return result
	}
	for i := range result {
		parsed, err := url.Parse(result[i].URL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		query := parsed.Query()
		query.Set("metadata_owner_mxid", mxid)
		parsed.RawQuery = query.Encode()
		result[i].URL = parsed.String()
	}
	return result
}
