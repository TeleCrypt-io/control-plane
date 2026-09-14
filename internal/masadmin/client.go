// Package masadmin is a client for MAS 1.23.0's admin API used by Janitor and Plan.
// The paths, authentication, response fields, and pagination below implement MAS's current
// admin API contract:
//
//   - crates/router/src/endpoints.rs — OAuth2TokenEndpoint's path is "/oauth2/token" (same
//     no-/auth-prefix convention internal/masreg already uses against the MAS internal origin).
//   - crates/handlers/src/oauth2/token.rs (client_credentials_grant) and
//     crates/axum-utils/src/client_authorization.rs (Credentials::verify) — client_credentials
//     authentication is checked against the client's *registered* token_endpoint_auth_method:
//     ClientSecretPost only matches a client configured for client_secret_post, ClientSecretBasic
//     only matches one configured for client_secret_basic. The admin client here is provisioned
//     as client_secret_basic, so sending the secret in the POST body instead of the Authorization
//     header fails with invalid_client. This client always sends HTTP Basic.
//   - crates/handlers/src/admin/mod.rs — the whole admin API is mounted at "/api/admin/v1".
//   - crates/handlers/src/admin/call_context.rs — every admin endpoint requires a bearer token
//     whose session scope contains "urn:mas:admin".
//   - crates/handlers/src/admin/v1/users/list.rs — GET /api/admin/v1/users returns User
//     resources with username, created_at, locked_at, and deactivated_at. No email field on User
//     itself — see user_emails below for email presence.
//   - crates/handlers/src/admin/v1/users/lock.rs — POST
//     /api/admin/v1/users/{ulid}/lock changes the reversible account lock. Janitor deliberately
//     has no unlock capability; Plan exposes manual recovery to the paying team owner.
//   - crates/handlers/src/admin/v1/user_emails/list.rs — GET /api/admin/v1/user-emails returns
//     UserEmail resources: {created_at, user_id, email}. Supports filter[user]=<ulid> but is also
//     listable unfiltered, so ListUserEmails fetches the whole list once per sweep and the caller
//     builds a user_id set locally, rather than this client issuing one filtered query per user.
//   - crates/handlers/src/admin/params.rs, crates/handlers/src/admin/response.rs — cursor
//     pagination: page[first]=N to page forward, page[after]=<cursor> to continue (the cursor is
//     just the previous page's last resource ID); count=false skips MAS's incidental COUNT(*)
//     query since this client never needs a total; a response's "links.next" key is present iff
//     there is a next page.
package masadmin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/TeleCrypt-io/controlplane/internal/httpdiag"
	"github.com/TeleCrypt-io/controlplane/internal/jsonbody"
)

// ErrUserNotFound is returned by LockUser when MAS reports the ULID doesn't exist (404).
var ErrUserNotFound = errors.New("masadmin: user not found")

func appendResponseBodyCloseError(result *error, body io.ReadCloser) {
	if closeErr := body.Close(); closeErr != nil {
		*result = errors.Join(*result, httpdiag.WrapCause("masadmin response body close", closeErr))
	}
}

// listPageSize is the page[first] value used for both ListUsers and ListUserEmails. MAS's own
// default (10, per admin/params.rs) is fine correctness-wise but wasteful for a sweep that always
// wants the full list — a larger page keeps the round-trip count low without guessing at prod
// scale.
const listPageSize = 100

const (
	maxMASIdentifierBytes = 255
	maxMASEmailBytes      = 320
	maxMASTokenBytes      = 8 << 10
	maxMASTokenLifetime   = 24 * time.Hour
)

// tokenSafetyMargin keeps a cached token from being handed out so close to its ~300s expiry that
// it might lapse mid-request.
const tokenSafetyMargin = 15 * time.Second

// Client talks to one MAS deployment's admin API, holding a standing client_credentials
// (client_secret_basic) admin credential. Safe for concurrent use.
type Client struct {
	baseURL      string
	clientID     string
	clientSecret string
	httpClient   *http.Client

	mu          sync.Mutex
	cachedToken string
	tokenExpiry time.Time
}

// NewClient targets the MAS admin origin (e.g. http://127.0.0.1:8081, no /auth prefix) with the given
// admin
// client_credentials client_id/client_secret.
func NewClient(baseURL, clientID, clientSecret string) *Client {
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   &http.Client{Timeout: 30 * time.Second, Transport: noProxyTransport(), CheckRedirect: rejectRedirects},
	}
}

// User is one MAS account, as returned by GET /api/admin/v1/users.
type User struct {
	ID            string // ULID
	Username      string
	CreatedAt     time.Time
	LockedAt      *time.Time
	DeactivatedAt *time.Time
}

// UserEmail is one email attached to a MAS account, as returned by GET /api/admin/v1/user-emails.
type UserEmail struct {
	ID        string // ULID
	UserID    string // the owning user's ULID
	Email     string
	CreatedAt time.Time
}

// token returns a valid bearer token, fetching a fresh one via client_credentials if the cached
// one is missing or within tokenSafetyMargin of expiry. A one-shot sweep normally fetches one
// token; the cache also keeps retries within that sweep efficient.
func (c *Client) token(ctx context.Context) (token string, resultErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cachedToken != "" && time.Now().Before(c.tokenExpiry.Add(-tokenSafetyMargin)) {
		return c.cachedToken, nil
	}

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"urn:mas:admin"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/oauth2/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret) // client_secret_basic — see package doc

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", masadminTransportError("masadmin: fetch token", err)
	}
	if resp.StatusCode != http.StatusOK {
		description, drainErr := describeError(resp)
		statusErr := fmt.Errorf("masadmin: fetch token: %s", description)
		closeErr := httpdiag.WrapCause("masadmin response body close", resp.Body.Close())
		return "", errors.Join(statusErr, drainErr, closeErr)
	}
	defer func() { appendResponseBodyCloseError(&resultErr, resp.Body) }()

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := jsonbody.Decode(resp.Body, &out); err != nil {
		return "", fmt.Errorf("masadmin: decode token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("masadmin: token response had no access_token")
	}
	if !validMASField(out.AccessToken, maxMASTokenBytes) {
		return "", fmt.Errorf("masadmin: token response had an invalid access_token")
	}
	if out.ExpiresIn <= 0 || out.ExpiresIn > int(maxMASTokenLifetime/time.Second) {
		return "", fmt.Errorf("masadmin: token response had an invalid expires_in")
	}

	c.cachedToken = out.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return c.cachedToken, nil
}

// resource is one JSON:API-ish resource envelope, shared by users and user-emails responses.
type resource[T any] struct {
	ID         string `json:"id"`
	Attributes T      `json:"attributes"`
}

type paginatedResponse[T any] struct {
	Data  []resource[T] `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

type userAttrs struct {
	Username      string     `json:"username"`
	CreatedAt     time.Time  `json:"created_at"`
	LockedAt      *time.Time `json:"locked_at"`
	DeactivatedAt *time.Time `json:"deactivated_at"`
}

type emailAttrs struct {
	CreatedAt time.Time `json:"created_at"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
}

// ListUsers returns every MAS user account, paging through the full result set via page[after]
// cursors.
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	var out []User
	after := ""
	seenCursors := map[string]struct{}{}
	for {
		var page paginatedResponse[userAttrs]
		if err := c.get(ctx, "/api/admin/v1/users?"+listQuery(after), &page); err != nil {
			return nil, fmt.Errorf("masadmin: list users: %w", err)
		}
		for _, r := range page.Data {
			if !validMASULID(r.ID) || !validMASUsername(r.Attributes.Username) || r.Attributes.CreatedAt.IsZero() {
				return nil, fmt.Errorf("masadmin: list users returned an invalid user identity")
			}
			out = append(out, User{
				ID:            r.ID,
				Username:      r.Attributes.Username,
				CreatedAt:     r.Attributes.CreatedAt,
				LockedAt:      r.Attributes.LockedAt,
				DeactivatedAt: r.Attributes.DeactivatedAt,
			})
		}
		if page.Links.Next == "" {
			break
		}
		if len(page.Data) == 0 {
			return nil, fmt.Errorf("masadmin: list users returned a next page without data")
		}
		next := page.Data[len(page.Data)-1].ID
		if next == "" || next == after {
			return nil, fmt.Errorf("masadmin: list users returned a non-progressing cursor")
		}
		if _, seen := seenCursors[next]; seen {
			return nil, fmt.Errorf("masadmin: list users returned a cursor cycle")
		}
		seenCursors[next] = struct{}{}
		after = next
	}
	return out, nil
}

// ListUserEmails returns every email attached to any MAS account, paging through the full result
// set via page[after] cursors. Unfiltered — the caller builds a user_id set locally rather than
// this client issuing one filtered (filter[user]=...) query per candidate user.
func (c *Client) ListUserEmails(ctx context.Context) ([]UserEmail, error) {
	var out []UserEmail
	after := ""
	seenCursors := map[string]struct{}{}
	for {
		var page paginatedResponse[emailAttrs]
		if err := c.get(ctx, "/api/admin/v1/user-emails?"+listQuery(after), &page); err != nil {
			return nil, fmt.Errorf("masadmin: list user emails: %w", err)
		}
		for _, r := range page.Data {
			if !validMASULID(r.ID) || !validMASULID(r.Attributes.UserID) || !validMASField(r.Attributes.Email, maxMASEmailBytes) || r.Attributes.CreatedAt.IsZero() {
				return nil, fmt.Errorf("masadmin: list user emails returned an invalid email identity")
			}
			out = append(out, UserEmail{
				ID:        r.ID,
				UserID:    r.Attributes.UserID,
				Email:     r.Attributes.Email,
				CreatedAt: r.Attributes.CreatedAt,
			})
		}
		if page.Links.Next == "" {
			break
		}
		if len(page.Data) == 0 {
			return nil, fmt.Errorf("masadmin: list user emails returned a next page without data")
		}
		next := page.Data[len(page.Data)-1].ID
		if next == "" || next == after {
			return nil, fmt.Errorf("masadmin: list user emails returned a non-progressing cursor")
		}
		if _, seen := seenCursors[next]; seen {
			return nil, fmt.Errorf("masadmin: list user emails returned a cursor cycle")
		}
		seenCursors[next] = struct{}{}
		after = next
	}
	return out, nil
}

func listQuery(after string) string {
	v := url.Values{}
	v.Set("count", "false")
	v.Set("page[first]", strconv.Itoa(listPageSize))
	if after != "" {
		v.Set("page[after]", after)
	}
	return v.Encode()
}

// GetUser returns the current authoritative state of one MAS account.
func (c *Client) GetUser(ctx context.Context, userID string) (User, error) {
	if !validMASULID(userID) {
		return User{}, fmt.Errorf("masadmin: get user: invalid user identity")
	}
	var out struct {
		Data resource[userAttrs] `json:"data"`
	}
	if err := c.get(ctx, "/api/admin/v1/users/"+url.PathEscape(userID), &out); err != nil {
		return User{}, fmt.Errorf("masadmin: get user: %w", err)
	}
	if !validMASULID(userID) || out.Data.ID != userID || !validMASUsername(out.Data.Attributes.Username) || out.Data.Attributes.CreatedAt.IsZero() {
		return User{}, fmt.Errorf("masadmin: get user response had unexpected identity")
	}
	return User{
		ID:            out.Data.ID,
		Username:      out.Data.Attributes.Username,
		CreatedAt:     out.Data.Attributes.CreatedAt,
		LockedAt:      out.Data.Attributes.LockedAt,
		DeactivatedAt: out.Data.Attributes.DeactivatedAt,
	}, nil
}

// GetUserByUsername resolves a local Matrix account to its MAS identity and lock state.
func (c *Client) GetUserByUsername(ctx context.Context, username string) (User, error) {
	if !validMASUsername(username) {
		return User{}, fmt.Errorf("masadmin: get user: invalid username")
	}
	var out struct {
		Data resource[userAttrs] `json:"data"`
	}
	if err := c.get(ctx, "/api/admin/v1/users/by-username/"+url.PathEscape(username), &out); err != nil {
		return User{}, fmt.Errorf("masadmin: get user by username: %w", err)
	}
	if !validMASULID(out.Data.ID) || out.Data.Attributes.Username != username || out.Data.Attributes.CreatedAt.IsZero() {
		return User{}, fmt.Errorf("masadmin: get user by username response had unexpected identity")
	}
	return User{ID: out.Data.ID, Username: out.Data.Attributes.Username, CreatedAt: out.Data.Attributes.CreatedAt, LockedAt: out.Data.Attributes.LockedAt, DeactivatedAt: out.Data.Attributes.DeactivatedAt}, nil
}

// HasUserEmail checks email presence with MAS's filtered user-emails endpoint. It intentionally
// fetches only one resource: the caller only needs presence, not the email value.
func (c *Client) HasUserEmail(ctx context.Context, userID string) (bool, error) {
	if !validMASULID(userID) {
		return false, fmt.Errorf("masadmin: check user email: invalid user identity")
	}
	query := url.Values{
		"count":        {"false"},
		"filter[user]": {userID},
	}
	var page paginatedResponse[emailAttrs]
	if err := c.get(ctx, "/api/admin/v1/user-emails?"+query.Encode(), &page); err != nil {
		return false, fmt.Errorf("masadmin: check user email: %w", err)
	}
	if len(page.Data) == 0 && page.Links.Next != "" {
		return false, fmt.Errorf("masadmin: email presence response was not authoritative")
	}
	for _, resource := range page.Data {
		if !validMASULID(resource.ID) || resource.Attributes.UserID != userID || !validMASField(resource.Attributes.Email, maxMASEmailBytes) || resource.Attributes.CreatedAt.IsZero() {
			return false, fmt.Errorf("masadmin: email presence response had unexpected owner")
		}
	}
	return len(page.Data) != 0, nil
}

// LockUser locks the given MAS user (by ULID) — reversible, not a deactivation. Returns
// ErrUserNotFound if MAS reports no such user.
func (c *Client) LockUser(ctx context.Context, userID string) error {
	if !validMASULID(userID) {
		return fmt.Errorf("masadmin: lock user: invalid user identity")
	}
	attrs, err := c.changeUserLock(ctx, userID, "lock")
	if err != nil {
		return err
	}
	if attrs.LockedAt == nil {
		return fmt.Errorf("masadmin: lock user: response had no locked_at")
	}
	return nil
}

// UnlockUser reverses an account lock. Janitor does not call this; recovery is manual.
func (c *Client) UnlockUser(ctx context.Context, userID string) error {
	if !validMASULID(userID) {
		return fmt.Errorf("masadmin: unlock user: invalid user identity")
	}
	attrs, err := c.changeUserLock(ctx, userID, "unlock")
	if err != nil {
		return err
	}
	if attrs.LockedAt != nil {
		return fmt.Errorf("masadmin: unlock user: response remained locked")
	}
	return nil
}

func (c *Client) changeUserLock(ctx context.Context, userID, action string) (attrs userAttrs, resultErr error) {
	token, err := c.token(ctx)
	if err != nil {
		return userAttrs{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/admin/v1/users/"+url.PathEscape(userID)+"/"+action, nil)
	if err != nil {
		return userAttrs{}, errors.New("masadmin: create " + action + " request failed")
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return userAttrs{}, masadminTransportError("masadmin: "+action+" user", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		body, readErr, closeErr := httpdiag.ReadAndClose(resp.Body)
		return userAttrs{}, errors.Join(fmt.Errorf("masadmin: "+action+" user: %w", ErrUserNotFound), httpdiag.NewResponseError("masadmin: "+action+" user not-found response", resp.StatusCode, body, readErr, closeErr))
	}
	if resp.StatusCode != http.StatusOK {
		description, drainErr := describeError(resp)
		statusErr := fmt.Errorf("masadmin: "+action+" user: %s", description)
		closeErr := httpdiag.WrapCause("masadmin response body close", resp.Body.Close())
		return userAttrs{}, errors.Join(statusErr, drainErr, closeErr)
	}
	defer func() { appendResponseBodyCloseError(&resultErr, resp.Body) }()
	var out struct {
		Data resource[userAttrs] `json:"data"`
	}
	if err := jsonbody.Decode(resp.Body, &out); err != nil {
		return userAttrs{}, fmt.Errorf("masadmin: decode "+action+" user: %w", err)
	}
	if out.Data.ID != userID || !validMASUsername(out.Data.Attributes.Username) || out.Data.Attributes.CreatedAt.IsZero() {
		return userAttrs{}, fmt.Errorf("masadmin: %s user response had unexpected identity", action)
	}
	return out.Data.Attributes, nil
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

var masUsernamePattern = regexp.MustCompile(`^[0-9a-z=_+\-./]+$`)

// MAS identifies users and user-email resources with canonical 26-character ULIDs. Keeping this
// check separate from the generic field bound prevents malformed upstream identities from becoming
// Matrix IDs, lock paths, pagination cursors, or durable digest cursors.
func validMASULID(value string) bool {
	if len(value) != 26 || value[0] > '7' {
		return false
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i := range value {
		if !strings.ContainsRune(alphabet, rune(value[i])) {
			return false
		}
	}
	return true
}

func validMASUsername(value string) bool {
	return validMASField(value, maxMASIdentifierBytes) && masUsernamePattern.MatchString(value)
}

// ValidMXID verifies the exact local Matrix identity Janitor would derive from a MAS username.
// MAS bounds the username field independently, but Matrix bounds the complete user ID; callers
// must supply the already validated deployment server name so a foreign or oversized identity is
// never used for a mutation or durable verification lookup.
func ValidMXID(username, serverName string) bool {
	return validMASUsername(username) && serverName != "" && len("@"+username+":"+serverName) <= maxMASIdentifierBytes
}

// get issues an authenticated GET against path (relative to baseURL) and decodes a 200 JSON body
// into out.
func (c *Client) get(ctx context.Context, path string, out any) (resultErr error) {
	token, err := c.token(ctx)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return errors.New("masadmin: create request failed")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return masadminTransportError("masadmin: request", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		body, readErr, closeErr := httpdiag.ReadAndClose(resp.Body)
		return errors.Join(ErrUserNotFound, httpdiag.NewResponseError("masadmin not-found response", resp.StatusCode, body, readErr, closeErr))
	}
	if resp.StatusCode != http.StatusOK {
		description, drainErr := describeError(resp)
		closeErr := httpdiag.WrapCause("masadmin response body close", resp.Body.Close())
		return errors.Join(fmt.Errorf("%s", description), drainErr, closeErr)
	}
	defer func() { appendResponseBodyCloseError(&resultErr, resp.Body) }()
	return jsonbody.Decode(resp.Body, out)
}

func rejectRedirects(*http.Request, []*http.Request) error {
	return errors.New("MAS admin redirects are disabled")
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

func masadminTransportError(prefix string, err error) error {
	return httpdiag.WrapCause(prefix, err)
}

// describeError reads the complete response body. The caller closes the response so any close
// failure can be joined with the status and read failures at that boundary.
func describeError(resp *http.Response) (string, error) {
	body, readErr := httpdiag.ReadBody(resp.Body)
	diagnostic := fmt.Sprintf("status %d", resp.StatusCode)
	if body != "" {
		diagnostic += ": body=" + strconv.Quote(body)
	}
	if readErr != nil {
		return diagnostic, httpdiag.WrapCause("masadmin error response read", readErr)
	}
	return diagnostic, nil
}
