// Package masreg drives MAS 1.23.0's public password-registration and OAuth device flows as a
// plain HTTP client — the same request sequence a browser runs, with no admin credentials or
// pre-registered OAuth client involved.
//
// The endpoint sequence and form field names below implement the MAS 1.23.0 public contract:
//   - crates/handlers/src/views/register/mod.rs — GET /register redirects (303) straight to
//     /register/password when password registration is enabled and no upstream OAuth provider
//     is configured; otherwise it renders a combined provider-choice page instead (not handled
//     here — see the package-level "assumes no upstream OAuth provider" note below).
//   - crates/router/src/endpoints.rs — route paths: PasswordRegister is "/register/password",
//     RegisterDisplayName is "/register/steps/{id}/display-name", RegisterFinish is
//     "/register/steps/{id}/finish".
//   - crates/handlers/src/views/register/password.rs — RegisterForm{username, email, password,
//     password_confirm, accept_terms}; on success redirects (303) to RegisterFinish.
//   - crates/handlers/src/views/register/steps/finish.rs — GET is the orchestrator: redirects to
//     whichever step (registration token / verify-email / display-name) isn't done yet, then
//     completes the registration (creates the MAS user row) and redirects away from /register.
//   - crates/handlers/src/views/register/steps/display_name.rs — DisplayNameForm{action,
//     display_name}; action="skip" makes MAS default the display name to the username, the same
//     default Synapse itself would pick.
//   - crates/axum-utils/src/csrf.rs — ProtectedForm: the CSRF token lives in an opaque "csrf"
//     cookie (cookiejar carries it automatically) and must be echoed back as a hidden "csrf" form
//     field; there is no Origin/Referer check, only the token match.
//   - crates/handlers/src/oauth2/device/link.rs — GET /link returns a CSRF-protected form;
//     POST /link with the echoed token and user code redirects (303) to the consent page.
//   - templates/pages/register/password.html, templates/pages/register/steps/display_name.html —
//     exact input names, including the hidden "csrf" and "action" fields.
//
// Registration form steps succeed through 303 redirects. The device-consent POST is the
// exception: MAS 1.23 returns a 200 HTML response on the same consent route. net/http.Client's
// default redirect policy converts a POST into a followed GET on a 303, so the registration part
// of RegisterAndAuthorizeDevice issues one explicit HTTP call per logical step and lets the client
// follow the intermediate hops transparently — the same way a browser would.
package masreg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/TeleCrypt-io/controlplane/internal/httpdiag"
	"github.com/TeleCrypt-io/controlplane/internal/jsonbody"
	"github.com/TeleCrypt-io/controlplane/internal/registrationfailure"
)

// Client drives the registration flow against one MAS deployment. Safe for concurrent use: each
// RegisterAndAuthorizeDevice call runs in its own session with a fresh cookie jar. The jar
// isolation matters even for strictly sequential calls — a jar reused across registrations would
// present the previous account's live MAS session cookie on the next GET /register, and MAS
// redirects an already-authenticated visitor away from the form instead of serving it.
type Client struct {
	baseURL string
}

var (
	errMASPublicRedirect     = errors.New("MAS public OAuth redirects are disabled")
	errMASRedirectNoSource   = errors.New("MAS registration redirect had no source response")
	errMASRedirectLimit      = errors.New("MAS registration exceeded redirect limit")
	errMASBodyReplayRedirect = errors.New("MAS registration rejected a body-preserving redirect")
	errMASRedirectStatus     = errors.New("MAS registration requires a 303 redirect to GET")
	errMASRedirectOrigin     = errors.New("MAS redirected outside its configured origin")
	errMASRedirectUnsafeURL  = errors.New("MAS registration redirected to an unsafe URL")
	errMASRedirectUnexpected = errors.New("MAS registration redirected outside the expected flow")
)

var masRequestPolicyErrors = [...]error{
	errMASPublicRedirect,
	errMASRedirectNoSource,
	errMASRedirectLimit,
	errMASBodyReplayRedirect,
	errMASRedirectStatus,
	errMASRedirectOrigin,
	errMASRedirectUnsafeURL,
	errMASRedirectUnexpected,
}

const (
	maxMASOAuthFieldBytes     = 8 << 10
	maxMASDeviceLifetime      = 20 * time.Minute
	maxMASDeviceInterval      = 5 * time.Minute
	maxMASAccessLifetime      = 24 * time.Hour
	maxMatrixIdentityBytes    = 255
)

// NewClient targets the exact public MAS origin (for example,
// https://backend.stage.telecrypt.io/auth); registration binds all browser and OAuth calls to it.
func NewClient(baseURL string) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/")}
}

func validateSameOrigin(baseRaw, targetRaw string) error {
	base, err := parseOriginURL(baseRaw, false)
	if err != nil {
		return fmt.Errorf("invalid MAS base URL")
	}
	target, err := parseOriginURL(targetRaw, true)
	if err != nil {
		return fmt.Errorf("invalid backend URL")
	}
	if !strings.EqualFold(base.Scheme, target.Scheme) ||
		!strings.EqualFold(base.Hostname(), target.Hostname()) ||
		effectiveOriginPort(base) != effectiveOriginPort(target) {
		return fmt.Errorf("backend URL must have the same origin as MAS")
	}
	return nil
}

func parseOriginURL(raw string, target bool) (*url.URL, error) {
	if raw == "" || len(raw) > maxMASOAuthFieldBytes {
		return nil, errors.New("origin URL is empty or too large")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" {
		return nil, errors.New("unsafe origin URL")
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return nil, errors.New("unsupported origin URL scheme")
	}
	if target && u.Path != "" && u.Path != "/" {
		return nil, errors.New("backend URL must not contain a path")
	}
	return u, nil
}

func effectiveOriginPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

// session is the HTTP state of one RegisterAndAuthorizeDevice call: one cookie jar, one client,
// discarded after.
type session struct {
	baseURL          string
	baseURLParsed    *url.URL
	httpClient       *http.Client
	publicHTTPClient *http.Client // test seam; production always uses the credential-free default below
}

// DeviceTokens is the complete, short-lived result of the public OAuth device grant. Its client
// ID and token endpoint are returned because the caller must retain them to refresh the token;
// masreg itself keeps no state after RegisterAndAuthorizeDevice returns.
type DeviceTokens struct {
	AccessToken   string
	RefreshToken  string
	ExpiresIn     int
	ClientID      string
	Issuer        string
	TokenEndpoint string
	UserID        string
}

var csrfFieldRe = regexp.MustCompile(`name="csrf"\s+value="([^"]*)"`)

// extractCSRF returns "" if the page has no CSRF field — true of the final landing page after
// registration completes, which callers that no longer need a token simply ignore.
func extractCSRF(body []byte) string {
	m := csrfFieldRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// RegisterAndAuthorizeDevice creates an account through MAS's public forms, dynamically
// registers a public native OAuth client, grants a Matrix device through the authenticated MAS
// session, and polls the public token endpoint. The cookie jar is local to this call and is
// discarded before return.
func (c *Client) RegisterAndAuthorizeDevice(
	ctx context.Context, username, password, deviceID, clientURI string,
) (*DeviceTokens, error) {
	if !validRegistrationUsername(username) || !validMASField(password, maxMASOAuthFieldBytes) ||
		!validMatrixDeviceID(deviceID) {
		return nil, registrationfailure.WithKind(registrationfailure.StageInternal, registrationfailure.KindInvariant, errors.New("registration identity or credential is invalid"))
	}
	if err := validateSameOrigin(c.baseURL, clientURI); err != nil {
		return nil, registrationfailure.WithKind(registrationfailure.StageInternal, registrationfailure.KindInvariant, err)
	}
	s, err := c.registerSession(ctx, username, password)
	if err != nil {
		return nil, err
	}
	clientID, err := s.registerPublicNativeClient(ctx, clientURI)
	if err != nil {
		return nil, fmt.Errorf("register public OAuth client: %w", err)
	}
	device, err := s.startDeviceAuthorization(ctx, clientID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("start device authorization: %w", err)
	}
	if err := s.approveDeviceAuthorization(ctx, device.UserCode); err != nil {
		return nil, fmt.Errorf("approve device authorization: %w", err)
	}
	tokens, err := s.pollDeviceToken(ctx, clientID, device)
	if err != nil {
		return nil, fmt.Errorf("poll device token: %w", err)
	}
	tokens.ClientID = clientID
	// MAS's issuer is its configured base URI, whose canonical form has a trailing slash.
	tokens.Issuer = c.baseURL + "/"
	tokens.TokenEndpoint = c.baseURL + "/oauth2/token"
	userID, returnedDeviceID, err := s.whoAmI(ctx, clientURI, tokens.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("validate OAuth token identity: %w", err)
	}
	if returnedDeviceID != deviceID {
		return nil, registrationfailure.WithKind(registrationfailure.StageIdentity, registrationfailure.KindInvariant, errors.New("OAuth token returned unexpected device_id"))
	}
	tokens.UserID = userID
	return tokens, nil
}

func (c *Client) registerSession(ctx context.Context, username, password string) (*session, error) {
	jar, err := cookiejar.New(nil) // nil PublicSuffixList: this client only ever talks to one host
	if err != nil {
		return nil, registrationfailure.WithKind(registrationfailure.StageInternal, registrationfailure.KindInvariant, fmt.Errorf("create MAS cookie jar: %w", err))
	}
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, registrationfailure.WithKind(registrationfailure.StageInternal, registrationfailure.KindInvariant, err)
	}
	s := &session{baseURL: c.baseURL, baseURLParsed: base}
	s.httpClient = &http.Client{
		Timeout:       30 * time.Second,
		Transport:     noProxyTransport(),
		Jar:           jar,
		CheckRedirect: registrationRedirectPolicy(base),
	}
	if err := s.register(ctx, username, password); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *session) publicClient() *http.Client {
	if s.publicHTTPClient != nil {
		return s.publicHTTPClient
	}
	s.publicHTTPClient = newPublicHTTPClient()
	return s.publicHTTPClient
}

func newPublicHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: noProxyTransport(),
		// Public OAuth endpoints must never redirect: a 307/308 could otherwise replay a device
		// code or bearer token to an attacker-controlled origin.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errMASPublicRedirect
		},
	}
}

func registrationRedirectPolicy(base *url.URL) func(*http.Request, []*http.Request) error {
	return func(next *http.Request, via []*http.Request) error {
		// net/http attaches the redirect response to the upcoming request passed as
		// next.Response. Requests in via are the already-sent requests and normally
		// have no Response field, so reading via[len(via)-1].Response rejects every
		// valid redirect before its method and origin can be checked.
		if len(via) == 0 || next == nil || next.Response == nil {
			return errMASRedirectNoSource
		}
		if len(via) >= 8 {
			return errMASRedirectLimit
		}
		previous := via[len(via)-1]
		status := next.Response.StatusCode
		if status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect {
			return errMASBodyReplayRedirect
		}
		if status != http.StatusSeeOther || next.Method != http.MethodGet || next.Body != nil {
			return errMASRedirectStatus
		}
		if !sameOriginURL(base, next.URL) {
			return errMASRedirectOrigin
		}
		if next.URL.User != nil || next.URL.RawQuery != "" || next.URL.ForceQuery ||
			next.URL.Fragment != "" || next.URL.RawPath != "" {
			return errMASRedirectUnsafeURL
		}
		if !validRegistrationTransition(base, previous.Method, previous.URL, next.URL) {
			return errMASRedirectUnexpected
		}
		return nil
	}
}

func sameOriginURL(left, right *url.URL) bool {
	return left != nil && right != nil &&
		strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) &&
		effectiveOriginPort(left) == effectiveOriginPort(right)
}

func validRegistrationTransition(base *url.URL, method string, from, to *url.URL) bool {
	fromPath, fromOK := relativeMASPath(base, from)
	toPath, toOK := relativeMASPath(base, to)
	if !fromOK || !toOK {
		return false
	}
	switch {
	case method == http.MethodGet && fromPath == "/register":
		return toPath == "/register/password"
	case method == http.MethodPost && fromPath == "/register/password":
		_, step, ok := registrationStep(toPath)
		return ok && step == "finish"
	case method == http.MethodGet:
		fromID, fromStep, ok := registrationStep(fromPath)
		if !ok || fromStep != "finish" {
			return false
		}
		toID, toStep, isStep := registrationStep(toPath)
		return (isStep && toID == fromID && toStep == "display-name") || isRegistrationCompletionPath(toPath)
	case method == http.MethodPost:
		fromID, fromStep, ok := registrationStep(fromPath)
		if ok && fromStep == "display-name" {
			toID, toStep, targetOK := registrationStep(toPath)
			return targetOK && toID == fromID && toStep == "finish"
		}
		if isDeviceConsentRelativePath(fromPath) {
			// MAS 1.23 completes consent with HTTP 200 on the same route. A redirect to
			// /device/complete is not an upstream contract and must remain rejected.
			return false
		}
		return !ok && fromPath == "/link" && isDeviceConsentRelativePath(toPath)
	default:
		return false
	}
}

func relativeMASPath(base, target *url.URL) (string, bool) {
	if !sameOriginURL(base, target) {
		return "", false
	}
	prefix := strings.TrimRight(base.Path, "/")
	if prefix != "" {
		if target.Path == prefix {
			return "/", true
		}
		if !strings.HasPrefix(target.Path, prefix+"/") {
			return "", false
		}
		return strings.TrimPrefix(target.Path, prefix), true
	}
	if !strings.HasPrefix(target.Path, "/") {
		return "", false
	}
	return target.Path, true
}

func registrationStep(path string) (id, step string, ok bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != 4 || parts[0] != "register" || parts[1] != "steps" ||
		!validFlowPathSegment(parts[2]) || (parts[3] != "finish" && parts[3] != "display-name") {
		return "", "", false
	}
	return parts[2], parts[3], true
}

func isDeviceConsentRelativePath(path string) bool {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	return len(parts) == 2 && parts[0] == "device" && parts[1] != "complete" && validFlowPathSegment(parts[1])
}

func validFlowPathSegment(value string) bool {
	if value == "" || len(value) > maxMatrixIdentityBytes {
		return false
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func isRegistrationCompletionPath(path string) bool {
	// These are the only completion locations exercised by Controlplane's current MAS 1.23
	// fixture. They are intentionally not a claim that MAS documents a broader redirect
	// contract: the disposable exact-image integration test is the release gate for this list.
	return path == "/" || path == "/welcome"
}

func noProxyTransport() http.RoundTripper {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{}
	}
	transport = transport.Clone()
	transport.Proxy = nil
	return transport
}

func (c *session) register(ctx context.Context, username, password string) error {
	// Step 1: GET /register -> (redirect, followed automatically) -> /register/password form.
	csrf, formURL, _, err := c.getForm(ctx, c.baseURL+"/register", username, password)
	if err != nil {
		return registrationfailure.Wrap(registrationfailure.StageRegistrationForm, fmt.Errorf("masreg: load register form: %w", err))
	}
	if !c.isRegistrationPath(formURL.Path) || !strings.HasSuffix(formURL.Path, "/register/password") {
		return registrationfailure.Wrap(registrationfailure.StageRegistrationForm, registrationfailure.Protocol(errors.New("masreg: expected the password-registration form; is an upstream OAuth provider configured?")))
	}
	if !validMASField(csrf, maxMASOAuthFieldBytes) {
		return registrationfailure.Wrap(registrationfailure.StageRegistrationForm, registrationfailure.Protocol(errors.New("masreg: no valid csrf token found on the password registration page")))
	}

	// Step 2: POST /register/password. Field names from password.html / password.rs's
	// RegisterForm. Email is deliberately left blank per the target provisioning flow.
	form := url.Values{
		"csrf":             {csrf},
		"username":         {username},
		"email":            {""},
		"password":         {password},
		"password_confirm": {password},
		"accept_terms":     {"on"}, // no-op if this deployment has no tos_uri configured
	}
	csrf, formURL, _, err = c.postForm(ctx, formURL.String(), form, username, password, csrf)
	if err != nil {
		return registrationfailure.Wrap(registrationfailure.StageRegistrationPassword, fmt.Errorf("masreg: submit password form: %w", err))
	}
	if !c.isRegistrationPath(formURL.Path) || !strings.Contains(formURL.Path, "/register/steps/") || !strings.HasSuffix(formURL.Path, "/display-name") {
		return registrationfailure.Wrap(registrationfailure.StageRegistrationPassword, registrationfailure.Protocol(errors.New("masreg: password registration did not reach the expected display-name step")))
	}
	if !validMASField(csrf, maxMASOAuthFieldBytes) {
		return registrationfailure.Wrap(registrationfailure.StageRegistrationPassword, registrationfailure.Protocol(errors.New("masreg: no valid csrf token found on the display-name step page")))
	}

	// Step 3: POST .../display-name with action=skip (display_name.rs: skip defaults the
	// display name to the username). The finish step (steps/finish.rs GET) then completes the
	// registration synchronously and redirects away from /register entirely.
	form = url.Values{
		"csrf":   {csrf},
		"action": {"skip"},
	}
	_, formURL, _, err = c.postForm(ctx, formURL.String(), form, username, password, csrf)
	if err != nil {
		return registrationfailure.Wrap(registrationfailure.StageRegistrationDisplayName, fmt.Errorf("masreg: submit display-name step: %w", err))
	}
	relativePath, completionOK := relativeMASPath(c.baseURLParsed, formURL)
	if c.isRegistrationPath(formURL.Path) || !completionOK || !isRegistrationCompletionPath(relativePath) {
		return registrationfailure.Wrap(registrationfailure.StageRegistrationDisplayName, registrationfailure.Protocol(errors.New("masreg: registration did not complete at the expected landing page")))
	}

	return nil
}

// isRegistrationPath accounts for MAS being published below a path prefix (for example
// https://backend.telecrypt.io/auth/). Redirects that stay inside /auth/register are incomplete
// registration, even though they do not begin at the origin root.
func (c *session) isRegistrationPath(path string) bool {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return false
	}
	prefix := strings.TrimRight(base.Path, "/") + "/register"
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

type deviceAuthorization struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
	ExpiresIn  int    `json:"expires_in"`
	Interval   int    `json:"interval"`
}

func (s *session) registerPublicNativeClient(ctx context.Context, clientURI string) (clientID string, resultErr error) {
	if !validMASField(clientURI, maxMASOAuthFieldBytes) {
		return "", registrationfailure.Wrap(registrationfailure.StageOAuthClient, registrationfailure.Invariant(errors.New("client_uri is invalid or too large")))
	}
	payload := struct {
		ClientName              string   `json:"client_name"`
		ClientURI               string   `json:"client_uri"`
		RedirectURIs            []string `json:"redirect_uris"`
		ApplicationType         string   `json:"application_type"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
	}{
		ClientName:              "TeleCrypt Registration agent",
		ClientURI:               clientURI,
		RedirectURIs:            []string{clientURI},
		ApplicationType:         "native",
		TokenEndpointAuthMethod: "none",
		GrantTypes: []string{
			"urn:ietf:params:oauth:grant-type:device_code",
			"refresh_token",
		},
		ResponseTypes: []string{},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", registrationfailure.Wrap(registrationfailure.StageOAuthClient, err)
	}
	// MAS 1.23.0's DynamicClientRegistration route is /oauth2/registration. The grant types
	// are explicit: MAS otherwise defaults to authorization_code, which cannot issue this device
	// grant or its refresh token.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/oauth2/registration", bytes.NewReader(b))
	if err != nil {
		return "", registrationfailure.Wrap(registrationfailure.StageOAuthClient, registrationfailure.Invariant(err))
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.publicClient().Do(req)
	if err != nil {
		return "", registrationfailure.Wrap(registrationfailure.StageOAuthClient, masRequestError(ctx, "register public OAuth client", err, clientURI))
	}
	defer func() { resultErr = errors.Join(resultErr, closeMASResponseBody(resp.Body, clientURI)) }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", registrationfailure.Wrap(registrationfailure.StageOAuthClient, unexpectedStatus(resp, clientURI))
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := jsonbody.Decode(resp.Body, &out, clientURI); err != nil {
		return "", registrationfailure.Wrap(registrationfailure.StageOAuthClient, registrationfailure.Protocol(fmt.Errorf("decode OAuth client response: %w", err)))
	}
	if !validMASField(out.ClientID, maxMASOAuthFieldBytes) {
		return "", registrationfailure.Wrap(registrationfailure.StageOAuthClient, registrationfailure.Protocol(errors.New("response has no client_id")))
	}
	return out.ClientID, nil
}

func (s *session) startDeviceAuthorization(ctx context.Context, clientID, deviceID string) (device *deviceAuthorization, resultErr error) {
	if !validMASField(clientID, maxMASOAuthFieldBytes) || !validMASField(deviceID, maxMatrixIdentityBytes) {
		return nil, registrationfailure.Wrap(registrationfailure.StageDeviceAuthorization, registrationfailure.Invariant(errors.New("device authorization identity is invalid")))
	}
	form := url.Values{
		"client_id": {clientID},
		"scope":     {"openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:" + deviceID},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/oauth2/device", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, registrationfailure.Wrap(registrationfailure.StageDeviceAuthorization, registrationfailure.Invariant(err))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.publicClient().Do(req)
	if err != nil {
		return nil, registrationfailure.Wrap(registrationfailure.StageDeviceAuthorization, masRequestError(ctx, "start device authorization", err, clientID, deviceID))
	}
	defer func() { resultErr = errors.Join(resultErr, closeMASResponseBody(resp.Body, clientID, deviceID)) }()
	if resp.StatusCode != http.StatusOK {
		return nil, registrationfailure.Wrap(registrationfailure.StageDeviceAuthorization, unexpectedStatus(resp, clientID, deviceID))
	}
	var out deviceAuthorization
	if err := jsonbody.Decode(resp.Body, &out, clientID, deviceID); err != nil {
		return nil, registrationfailure.Wrap(registrationfailure.StageDeviceAuthorization, registrationfailure.Protocol(fmt.Errorf("decode device authorization response: %w", err)))
	}
	if !validMASField(out.DeviceCode, maxMASOAuthFieldBytes) || !validMASField(out.UserCode, maxMASOAuthFieldBytes) || out.ExpiresIn <= 0 || out.ExpiresIn > int(maxMASDeviceLifetime/time.Second) {
		return nil, registrationfailure.Wrap(registrationfailure.StageDeviceAuthorization, registrationfailure.Protocol(errors.New("response is missing device authorization fields")))
	}
	if out.Interval <= 0 {
		out.Interval = 5
	}
	if out.Interval > int(maxMASDeviceInterval/time.Second) {
		return nil, registrationfailure.Wrap(registrationfailure.StageDeviceAuthorization, registrationfailure.Protocol(errors.New("response has an invalid polling interval")))
	}
	return &out, nil
}

func (s *session) approveDeviceAuthorization(ctx context.Context, userCode string) error {
	// MAS 1.23's /link page is a CSRF-protected GET form. POSTing its token and
	// the user code redirects (303) to the consent page, which has its own CSRF
	// token. See
	// crates/handlers/src/oauth2/device/link.rs and
	// templates/pages/device_link.html in matrix-authentication-service v1.23.0.
	linkURL, err := url.Parse(s.baseURL + "/link")
	if err != nil {
		return registrationfailure.Wrap(registrationfailure.StageDeviceConsent, registrationfailure.Invariant(err))
	}
	csrf, formURL, _, err := s.getForm(ctx, linkURL.String(), userCode)
	if err != nil {
		return registrationfailure.Wrap(registrationfailure.StageDeviceConsent, fmt.Errorf("load device link: %w", err))
	}
	if formURL == nil || formURL.Path != linkURL.Path {
		return registrationfailure.Wrap(registrationfailure.StageDeviceConsent, registrationfailure.Protocol(errors.New("device link form landed outside the expected path")))
	}
	if !validMASField(csrf, maxMASOAuthFieldBytes) {
		return registrationfailure.Wrap(registrationfailure.StageDeviceConsent, registrationfailure.Protocol(errors.New("no valid csrf token found on device link form")))
	}
	csrf, consentURL, _, err := s.postForm(ctx, formURL.String(), url.Values{
		"csrf": {csrf},
		"code": {userCode},
	}, csrf, userCode)
	if err != nil {
		return registrationfailure.Wrap(registrationfailure.StageDeviceConsent, fmt.Errorf("submit device code: %w", err))
	}
	if consentURL == nil || !s.isDeviceConsentPath(consentURL.Path) {
		return registrationfailure.Wrap(registrationfailure.StageDeviceConsent, registrationfailure.Protocol(errors.New("device link did not redirect to the expected consent path")))
	}
	if !validMASField(csrf, maxMASOAuthFieldBytes) {
		return registrationfailure.Wrap(registrationfailure.StageDeviceConsent, registrationfailure.Protocol(errors.New("no valid csrf token found on device consent page")))
	}
	_, completionURL, _, err := s.postForm(ctx, consentURL.String(), url.Values{
		"csrf":           {csrf},
		"confirm_device": {"on"},
		"action":         {"consent"},
	}, csrf, userCode)
	if err != nil {
		return registrationfailure.Wrap(registrationfailure.StageDeviceConsent, fmt.Errorf("submit device consent: %w", err))
	}
	consentPath, consentOK := relativeMASPath(s.baseURLParsed, consentURL)
	completionPath, completionOK := relativeMASPath(s.baseURLParsed, completionURL)
	// MAS 1.23 completes consent with HTTP 200 HTML on the same /device/{id} route. The
	// request helper has already rejected non-200 responses and unsafe URLs; this explicit
	// same-route check rejects fabricated completion redirects while retaining fail-closed flow.
	if !consentOK || !completionOK || consentPath != completionPath {
		return registrationfailure.Wrap(registrationfailure.StageDeviceConsent, registrationfailure.Protocol(errors.New("device consent did not complete on the consent route")))
	}
	return nil
}

func (s *session) isDeviceConsentPath(path string) bool {
	if s.baseURLParsed == nil {
		return false
	}
	target := *s.baseURLParsed
	target.Path = path
	relative, ok := relativeMASPath(s.baseURLParsed, &target)
	return ok && isDeviceConsentRelativePath(relative)
}

func (s *session) pollDeviceToken(ctx context.Context, clientID string, device *deviceAuthorization) (*DeviceTokens, error) {
	if device == nil || !validMASField(clientID, maxMASOAuthFieldBytes) || !validMASField(device.DeviceCode, maxMASOAuthFieldBytes) || !validMASField(device.UserCode, maxMASOAuthFieldBytes) || device.ExpiresIn <= 0 || device.ExpiresIn > int(maxMASDeviceLifetime/time.Second) || device.Interval <= 0 || device.Interval > int(maxMASDeviceInterval/time.Second) {
		return nil, registrationfailure.Wrap(registrationfailure.StageDeviceToken, registrationfailure.Invariant(errors.New("invalid device authorization state")))
	}
	deadline := time.Now().Add(time.Duration(device.ExpiresIn) * time.Second)
	interval := time.Duration(device.Interval) * time.Second
	var retryDiagnostics []error
	for {
		form := url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {device.DeviceCode},
			"client_id":   {clientID},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/oauth2/token", strings.NewReader(form.Encode()))
		if err != nil {
			return nil, registrationfailure.Wrap(registrationfailure.StageDeviceToken, registrationfailure.Invariant(err))
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := s.publicClient().Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, registrationfailure.Wrap(registrationfailure.StageDeviceToken, ctx.Err())
			}
			if err := waitForRetry(ctx, interval, deadline); err != nil {
				return nil, registrationfailure.Wrap(registrationfailure.StageDeviceToken, err)
			}
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
			diagnostic, readErr, closeErr := readAndCloseMASResponse(resp.StatusCode, resp.Body, clientID, device.DeviceCode, device.UserCode)
			retryDiagnostics = append(retryDiagnostics, diagnostic)
			if readErr != nil || closeErr != nil {
				return nil, registrationfailure.Wrap(registrationfailure.StageDeviceToken, registrationfailure.Protocol(errors.Join(errors.New("drain token response failed"), diagnostic)))
			}
			if err := waitForRetry(ctx, interval, deadline); err != nil {
				return nil, registrationfailure.Wrap(registrationfailure.StageDeviceToken, errors.Join(err, errors.Join(retryDiagnostics...)))
			}
			continue
		}
		rawBody, readErr, closeErr := httpdiag.ReadAndCloseBytes(resp.Body)
		responseDiagnostic := httpdiag.NewResponseError("MAS token response", resp.StatusCode, string(rawBody), readErr, closeErr, clientID, device.DeviceCode, device.UserCode)
		if readErr != nil || closeErr != nil {
			return nil, registrationfailure.Wrap(registrationfailure.StageDeviceToken, registrationfailure.Protocol(responseDiagnostic))
		}
		var out struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int    `json:"expires_in"`
			Error        string `json:"error"`
		}
		if decodeErr := jsonbody.Decode(bytes.NewReader(rawBody), &out, clientID, device.DeviceCode, device.UserCode); decodeErr != nil {
			return nil, registrationfailure.Wrap(registrationfailure.StageDeviceToken, registrationfailure.Protocol(errors.Join(responseDiagnostic, httpdiag.WrapCause("decode token response failed", decodeErr, clientID, device.DeviceCode, device.UserCode))))
		}
		if resp.StatusCode == http.StatusOK {
			if !validMASField(out.AccessToken, maxMASOAuthFieldBytes) || !validMASField(out.RefreshToken, maxMASOAuthFieldBytes) || out.ExpiresIn <= 0 || out.ExpiresIn > int(maxMASAccessLifetime/time.Second) {
				return nil, registrationfailure.Wrap(registrationfailure.StageDeviceToken, registrationfailure.Protocol(errors.Join(errors.New("token response is missing access_token, refresh_token, or expires_in"), responseDiagnostic)))
			}
			return &DeviceTokens{AccessToken: out.AccessToken, RefreshToken: out.RefreshToken, ExpiresIn: out.ExpiresIn}, nil
		}
		if out.Error != "authorization_pending" && out.Error != "slow_down" {
			return nil, registrationfailure.Wrap(registrationfailure.StageDeviceToken, registrationfailure.Upstream(responseDiagnostic))
		}
		retryDiagnostics = append(retryDiagnostics, responseDiagnostic)
		if out.Error == "slow_down" {
			if interval > maxMASDeviceInterval-5*time.Second {
				return nil, registrationfailure.Wrap(registrationfailure.StageDeviceToken, registrationfailure.Protocol(errors.Join(errors.New("device authorization polling interval exceeded limit"), errors.Join(retryDiagnostics...))))
			}
			interval += 5 * time.Second
		}
		if err := waitForRetry(ctx, interval, deadline); err != nil {
			return nil, registrationfailure.Wrap(registrationfailure.StageDeviceToken, errors.Join(err, errors.Join(retryDiagnostics...)))
		}
	}
}

// drainAndCloseMASResponse is retained for callers that only need an explicit connection-reuse
// drain. Status-aware paths use readAndCloseMASResponse so a retry response's sanitized body is
// retained when the operation ultimately fails.
func drainAndCloseMASResponse(body io.ReadCloser, redactions ...string) error {
	diagnostic, readErr, closeErr := readAndCloseMASResponse(0, body, redactions...)
	if readErr == nil && closeErr == nil {
		return nil
	}
	return diagnostic
}

func readAndCloseMASResponse(status int, body io.ReadCloser, redactions ...string) (diagnostic error, readErr, closeErr error) {
	bodyText, readErr, closeErr := httpdiag.ReadAndClose(body, redactions...)
	diagnostic = httpdiag.NewResponseError("MAS retry response", status, bodyText, readErr, closeErr, redactions...)
	return diagnostic, readErr, closeErr
}

func waitForRetry(ctx context.Context, interval time.Duration, deadline time.Time) error {
	if time.Now().Add(interval).After(deadline) {
		return registrationfailure.WithKind(registrationfailure.StageDeviceToken, registrationfailure.KindTimeout, errors.New("device authorization expired"))
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return registrationfailure.Wrap(registrationfailure.StageDeviceToken, ctx.Err())
	case <-timer.C:
		return nil
	}
}

func (s *session) whoAmI(ctx context.Context, homeserver, accessToken string) (string, string, error) {
	if !validMASField(accessToken, maxMASOAuthFieldBytes) {
		return "", "", registrationfailure.Wrap(registrationfailure.StageIdentity, registrationfailure.Invariant(errors.New("invalid access token")))
	}
	if err := validateSameOrigin(s.baseURL, homeserver); err != nil {
		return "", "", registrationfailure.Wrap(registrationfailure.StageIdentity, registrationfailure.Invariant(err))
	}
	u, err := url.Parse(homeserver)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", "", registrationfailure.Wrap(registrationfailure.StageIdentity, registrationfailure.Invariant(errors.New("invalid homeserver URL")))
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/_matrix/client/v3/account/whoami"
	u.RawQuery = ""
	u.Fragment = ""
	var retryDiagnostics []error
	// The caller's context is the only retry deadline. Keep retrying the known-safe
	// GET transport failures and provider-not-ready responses until the provider
	// succeeds, returns a non-transient response, or the caller stops the operation.
	for delay := 100 * time.Millisecond; ; delay *= 2 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return "", "", registrationfailure.Wrap(registrationfailure.StageIdentity, registrationfailure.Invariant(err))
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		resp, err := s.publicClient().Do(req)
		if err != nil {
			transportDiagnostic := masRequestError(nil, "identity transport", err, accessToken, homeserver)
			if ctx.Err() != nil {
				return "", "", registrationfailure.Wrap(registrationfailure.StageIdentity, errors.Join(ctx.Err(), transportDiagnostic, errors.Join(retryDiagnostics...)))
			}
			retryDiagnostics = append(retryDiagnostics, transportDiagnostic)
			if err := waitForContext(ctx, delay); err != nil {
				return "", "", registrationfailure.Wrap(registrationfailure.StageIdentity, errors.Join(err, errors.Join(retryDiagnostics...)))
			}
			continue
		}
		if resp.StatusCode == http.StatusOK {
			rawBody, readErr, closeErr := httpdiag.ReadAndCloseBytes(resp.Body)
			responseDiagnostic := httpdiag.NewResponseError("MAS identity response", resp.StatusCode, string(rawBody), readErr, closeErr, accessToken, homeserver)
			if readErr != nil || closeErr != nil {
				return "", "", registrationfailure.Wrap(registrationfailure.StageIdentity, registrationfailure.Protocol(responseDiagnostic))
			}
			var out struct {
				UserID   string `json:"user_id"`
				DeviceID string `json:"device_id"`
			}
			if decodeErr := jsonbody.Decode(bytes.NewReader(rawBody), &out, accessToken, homeserver); decodeErr != nil {
				return "", "", registrationfailure.Wrap(registrationfailure.StageIdentity, registrationfailure.Protocol(errors.Join(responseDiagnostic, httpdiag.WrapCause("decode identity response failed", decodeErr, accessToken, homeserver))))
			}
			if !validMatrixUserID(out.UserID) || !validMatrixDeviceID(out.DeviceID) {
				return "", "", registrationfailure.Wrap(registrationfailure.StageIdentity, registrationfailure.Protocol(errors.Join(errors.New("response is missing user_id or device_id"), responseDiagnostic)))
			}
			return out.UserID, out.DeviceID, nil
		}
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < http.StatusInternalServerError {
			statusErr := errors.Join(unexpectedStatus(resp, accessToken, homeserver), closeMASResponseBody(resp.Body, accessToken, homeserver))
			return "", "", registrationfailure.Wrap(registrationfailure.StageIdentity, statusErr)
		}
		diagnostic, readErr, closeErr := readAndCloseMASResponse(resp.StatusCode, resp.Body, accessToken, homeserver)
		retryDiagnostics = append(retryDiagnostics, diagnostic)
		if readErr != nil || closeErr != nil {
			return "", "", registrationfailure.Wrap(registrationfailure.StageIdentity, diagnostic)
		}
		if err := waitForContext(ctx, delay); err != nil {
			return "", "", registrationfailure.Wrap(registrationfailure.StageIdentity, errors.Join(err, errors.Join(retryDiagnostics...)))
		}
	}
}

func validMASField(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func validRegistrationUsername(value string) bool {
	if !validMASField(value, maxMatrixIdentityBytes) {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && !strings.ContainsRune("._=-/+", r) {
			return false
		}
	}
	return true
}

func validMatrixUserID(value string) bool {
	if !validMASField(value, maxMatrixIdentityBytes) || !strings.HasPrefix(value, "@") {
		return false
	}
	colon := strings.IndexByte(value[1:], ':')
	if colon < 1 {
		return false
	}
	colon++
	localpart, serverName := value[1:colon], value[colon+1:]
	if len(localpart) == 0 || len(serverName) == 0 {
		return false
	}
	for _, r := range localpart {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && !strings.ContainsRune("._=-/+", r) {
			return false
		}
	}
	return validMatrixServerName(serverName)
}

// validMatrixServerName accepts the Matrix server-name grammar without allowing URL syntax,
// Unicode confusables, userinfo, or query/fragment delimiters into the identity returned by MAS.
// Hostnames are deliberately lowercase because Controlplane's deployment identity is canonical.
func validMatrixServerName(value string) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	if strings.HasPrefix(value, "[") {
		close := strings.IndexByte(value, ']')
		if close < 0 || close == 1 || !strings.Contains(value[1:close], ":") {
			return false
		}
		if net.ParseIP(value[1:close]) == nil {
			return false
		}
		return validMatrixPort(value[close+1:])
	}
	host, port, hasPort := value, "", false
	if strings.Count(value, ":") > 1 {
		return false
	}
	if i := strings.LastIndexByte(value, ':'); i >= 0 {
		host, port, hasPort = value[:i], value[i+1:], true
	}
	if net.ParseIP(host) != nil {
		return !hasPort || validMatrixPort(":"+port)
	}
	if host == "" || len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return false
			}
		}
	}
	return !hasPort || validMatrixPort(":"+port)
}

func validMatrixPort(value string) bool {
	if value == "" {
		return true
	}
	if !strings.HasPrefix(value, ":") || len(value) == 1 {
		return false
	}
	port, err := strconv.ParseUint(value[1:], 10, 16)
	return err == nil && port != 0
}

func validMatrixDeviceID(value string) bool {
	if !validMASField(value, maxMatrixIdentityBytes) {
		return false
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && !strings.ContainsRune("._=-", r) {
			return false
		}
	}
	return true
}

func waitForContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// masRequestError preserves the complete sanitized cause while retaining the existing failure
// classification. Implementations can include URLs or credentials in Error(), so caller-known
// values and common credential fields are redacted without discarding the surrounding diagnostic.
func masRequestError(ctx context.Context, operation string, err error, redactions ...string) error {
	if ctx != nil && ctx.Err() != nil {
		return httpdiag.WrapCause(operation, ctx.Err(), redactions...)
	}
	if errors.Is(err, context.Canceled) {
		return httpdiag.WrapCause(operation, err, redactions...)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return httpdiag.WrapCause(operation, err, redactions...)
	}
	for _, known := range masRequestPolicyErrors {
		if errors.Is(err, known) {
			return registrationfailure.Protocol(httpdiag.WrapCause(operation, err, redactions...))
		}
	}
	return registrationfailure.Transport(httpdiag.WrapCause(operation, err, redactions...))
}

func unexpectedStatus(resp *http.Response, redactions ...string) error {
	body, readErr := httpdiag.ReadBody(resp.Body, redactions...)
	diagnostic := httpdiag.NewResponseError("MAS unexpected upstream status", resp.StatusCode, body, readErr, nil, redactions...)
	if readErr != nil {
		return registrationfailure.Transport(diagnostic)
	}
	return registrationfailure.Upstream(diagnostic)
}

func closeMASResponseBody(body io.ReadCloser, redactions ...string) error {
	if closeErr := body.Close(); closeErr != nil {
		return registrationfailure.Protocol(httpdiag.WrapCause("close MAS response body", closeErr, redactions...))
	}
	return nil
}

func (c *session) getForm(ctx context.Context, target string, redactions ...string) (csrf string, finalURL *url.URL, body []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", nil, nil, registrationfailure.Invariant(err)
	}
	return c.do(req, redactions...)
}

func (c *session) postForm(ctx context.Context, target string, form url.Values, redactions ...string) (csrf string, finalURL *url.URL, body []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return "", nil, nil, registrationfailure.Invariant(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req, redactions...)
}

// do issues req (following any redirects, per the package doc), and extracts the CSRF token from
// the final landing page's hidden form field so the caller can echo it in the next step.
func (c *session) do(req *http.Request, redactions ...string) (csrf string, finalURL *url.URL, body []byte, err error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", nil, nil, masRequestError(req.Context(), "MAS form request", err, redactions...)
	}
	defer func() { err = errors.Join(err, closeMASResponseBody(resp.Body, redactions...)) }()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		diagnostic := httpdiag.NewResponseError("MAS form response", resp.StatusCode, string(body), err, nil, redactions...)
		return "", nil, nil, registrationfailure.Transport(diagnostic)
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil, nil, registrationfailure.Upstream(httpdiag.NewResponseError("MAS form response", resp.StatusCode, string(body), nil, nil, redactions...))
	}
	if resp.Request == nil || resp.Request.URL == nil || !sameOriginURL(c.baseURLParsed, resp.Request.URL) ||
		resp.Request.URL.User != nil || resp.Request.URL.RawQuery != "" || resp.Request.URL.ForceQuery ||
		resp.Request.URL.Fragment != "" || resp.Request.URL.RawPath != "" {
		return "", nil, nil, registrationfailure.Protocol(errors.New("MAS form landed at an unsafe URL"))
	}
	return extractCSRF(body), resp.Request.URL, body, nil
}
