package masadmin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type countingBody struct {
	reader io.Reader
	read   int
	err    error
}

type masadminRoundTripFunc func(*http.Request) (*http.Response, error)

func (f masadminRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (b *countingBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	n, err := b.reader.Read(p)
	b.read += n
	return n, err
}

func (b *countingBody) Close() error { return nil }

type closeErrorBody struct {
	reader  io.Reader
	closeErr error
}

func (b *closeErrorBody) Read(p []byte) (int, error) { return b.reader.Read(p) }
func (b *closeErrorBody) Close() error               { return b.closeErr }

func testULID(seed string) string {
	digest := sha256.Sum256([]byte(seed))
	return "0" + strings.ToUpper(hex.EncodeToString(digest[:]))[:25]
}

func canonicalTestULID(value string) string {
	if validMASULID(value) {
		return value
	}
	return testULID(value)
}

func TestDescribeErrorDrainsAndSanitizesUpstreamBody(t *testing.T) {
	secret := "mas-client-secret-should-never-escape"
	body := append([]byte("prefix "+secret+" "), bytes.Repeat([]byte("x"), 256<<10)...)
	body = append(body, []byte(" tail")...)
	resp := &http.Response{StatusCode: http.StatusBadGateway, Body: &countingBody{reader: bytes.NewReader(body)}}

	got, err := describeError(resp, secret)
	if err != nil {
		t.Fatalf("describeError: %v", err)
	}
	if !strings.Contains(got, "prefix") || !strings.Contains(got, "tail") {
		t.Fatalf("describeError = %q, want complete response body", got)
	}
	if strings.Contains(got, secret) {
		t.Fatal("describeError returned sensitive upstream body")
	}
	reader := resp.Body.(*countingBody)
	if reader.read != len(body) {
		t.Fatalf("describeError read %d bytes, want complete body of %d", reader.read, len(body))
	}
}

func TestDescribeErrorPreservesDrainFailure(t *testing.T) {
	readErr := errors.New("MAS error response drain failed")
	resp := &http.Response{StatusCode: http.StatusBadGateway, Body: &countingBody{reader: strings.NewReader("error"), err: readErr}}

	got, err := describeError(resp)
	if !strings.HasPrefix(got, "status 502") || !errors.Is(err, readErr) || !strings.Contains(err.Error(), "MAS error response drain failed") {
		t.Fatalf("describeError = %q, %v, want complete status and preserved drain failure", got, err)
	}
}

func TestClientRejectsCrossOriginRedirects(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			calls := 0
			client := NewClient("https://mas.example", "client", "secret")
			client.httpClient.Transport = masadminRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{
					StatusCode: status,
					Header:     http.Header{"Location": {"https://attacker.example/steal"}},
					Body:       io.NopCloser(strings.NewReader("redirect")),
					Request:    r,
				}, nil
			})
			if _, err := client.ListUsers(context.Background()); err == nil {
				t.Fatal("ListUsers unexpectedly followed redirect")
			}
			if calls != 1 {
				t.Fatalf("transport calls = %d, want 1", calls)
			}
		})
	}
}

func TestClientDoesNotUseAmbientProxy(t *testing.T) {
	client := NewClient("https://mas.example", "client", "secret")
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client transport = %T, want *http.Transport", client.httpClient.Transport)
	}
	if transport.Proxy != nil {
		t.Fatalf("MAS admin transport proxy is enabled")
	}
}

func TestClientPreservesResponseCloseFailure(t *testing.T) {
	closeErr := errors.New("MAS response close failed")
	client := NewClient("https://mas.example", "client", "secret")
	client.cachedToken = "token"
	client.tokenExpiry = time.Now().Add(time.Hour)
	client.httpClient.Transport = masadminRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       &closeErrorBody{reader: strings.NewReader(`{"data":[]}`), closeErr: closeErr},
		}, nil
	})
	var out paginatedResponse[User]
	if err := client.get(context.Background(), "/api/admin/v1/users", &out); !errors.Is(err, closeErr) {
		t.Fatalf("MAS admin response error = %v, want close failure", err)
	}
}

func TestClientStatusDiagnosticRetainsSanitizedBodyAndCloseFailure(t *testing.T) {
	secret := "mas-client-secret"
	userID := testULID("diagnostic-user")
	closeErr := errors.New("close response failed for " + userID)
	client := NewClient("https://mas.example", "client", secret)
	client.cachedToken = "bearer-token"
	client.tokenExpiry = time.Now().Add(time.Hour)
	client.httpClient.Transport = masadminRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Body: &closeErrorBody{
				reader:   strings.NewReader("provider detail " + secret + " " + userID + " tail"),
				closeErr: closeErr,
			},
		}, nil
	})
	var out paginatedResponse[User]
	err := client.get(context.Background(), "/api/admin/v1/users/"+userID, &out)
	if err == nil || !strings.Contains(err.Error(), "tail") || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), userID) || !errors.Is(err, closeErr) {
		t.Fatalf("MAS admin status error = %v, want complete sanitized body and close failure", err)
	}
}

func TestClientDoesNotLeakCredentialsAcrossRedirect(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var targetCalls int
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetCalls++
				if got := r.Header.Get("Authorization"); got != "" {
					t.Errorf("redirect target received Authorization %q", got)
				}
			}))
			defer target.Close()
			redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", target.URL)
				w.WriteHeader(status)
			}))
			defer redirector.Close()

			client := NewClient(redirector.URL, "client", "secret")
			req, err := http.NewRequest(http.MethodGet, redirector.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer privileged")
			if _, err := client.httpClient.Do(req); err == nil {
				t.Fatal("admin client followed redirect")
			}
			if targetCalls != 0 {
				t.Fatalf("redirect target calls = %d, want 0", targetCalls)
			}
		})
	}
}

func TestUserErrorsDoNotExposeMASIDs(t *testing.T) {
	const userIDSeed = "01JMASUSERIDSHOULDNOTLEAK"
	userID := testULID(userIDSeed)
	transportErr := errors.New("dial failed for " + userID + " tail")
	client := NewClient("https://mas.example", "client", "secret")
	client.httpClient.Transport = masadminRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, transportErr
	})
	_, err := client.GetUser(context.Background(), userID)
	if err == nil || !strings.Contains(err.Error(), "tail") || strings.Contains(err.Error(), userID) || !errors.Is(err, transportErr) {
		t.Fatalf("GetUser error = %v, want complete sanitized transport cause", err)
	}
	badURLClient := NewClient(":", "client", "secret")
	_, err = badURLClient.GetUser(context.Background(), userID)
	if err == nil || strings.Contains(err.Error(), userID) {
		t.Fatalf("GetUser malformed-URL error = %v, want sanitized error without MAS ID", err)
	}
}

// fakeUser is the fakeMASAdmin server's in-memory notion of one MAS account.
type fakeUser struct {
	id        string
	username  string
	createdAt time.Time
	lockedAt  *time.Time
}

// fakeMASAdmin reproduces just enough of MAS 1.23.0's admin API — POST /oauth2/token
// (client_credentials, Basic-auth-only), GET /api/admin/v1/users and /user-emails (cursor
// pagination via page[first]/page[after]), and POST /api/admin/v1/users/{id}/lock — to
// exercise Client's HTTP mechanics end-to-end. See client.go's package doc for the MAS source
// files this is modeled on.
type fakeMASAdmin struct {
	clientID       string
	clientSecret   string
	tokenExpiresIn int // seconds

	mu           sync.Mutex
	tokenFetches int
	users        []*fakeUser
	emails       map[string]string // user id -> email
	cycleUsers   bool
	cycleEmails  bool
}

func newFakeMASAdmin(clientID, clientSecret string) *fakeMASAdmin {
	return &fakeMASAdmin{
		clientID:       clientID,
		clientSecret:   clientSecret,
		tokenExpiresIn: 300,
		emails:         map[string]string{},
	}
}

func (f *fakeMASAdmin) addUser(id, username string, createdAt time.Time, locked bool) *fakeUser {
	u := &fakeUser{id: canonicalTestULID(id), username: username, createdAt: createdAt}
	if locked {
		t := createdAt.Add(time.Hour)
		u.lockedAt = &t
	}
	f.mu.Lock()
	f.users = append(f.users, u)
	f.mu.Unlock()
	return u
}

func (f *fakeMASAdmin) addEmail(userID, email string) {
	f.mu.Lock()
	f.emails[canonicalTestULID(userID)] = email
	f.mu.Unlock()
}

func (f *fakeMASAdmin) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth2/token", f.handleToken)
	mux.HandleFunc("GET /api/admin/v1/users", f.handleListUsers)
	mux.HandleFunc("GET /api/admin/v1/users/{id}", f.handleGetUser)
	mux.HandleFunc("GET /api/admin/v1/user-emails", f.handleListEmails)
	mux.HandleFunc("POST /api/admin/v1/users/{id}/lock", f.handleLock)
	return httptest.NewServer(mux)
}

func (f *fakeMASAdmin) handleGetUser(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	id := r.PathValue("id")
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.id != id {
			continue
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": fakeResource[fakeUserAttrs]{
			Type: "user", ID: u.id,
			Attributes: fakeUserAttrs{Username: u.username, CreatedAt: u.createdAt, LockedAt: u.lockedAt},
		}}) //nolint:errcheck
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func (f *fakeMASAdmin) handleToken(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || user != f.clientID || pass != f.clientSecret {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"title":"invalid_client"}]}`)
		return
	}
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("grant_type") != "client_credentials" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"errors":[{"title":"unsupported grant_type"}]}`)
		return
	}
	if r.PostForm.Get("scope") != "urn:mas:admin" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"errors":[{"title":"unexpected scope"}]}`)
		return
	}
	// Real MAS rejects client_secret in the POST body for a client_secret_basic-registered client
	// (see client.go's package doc). Enforcing that here too catches a regression to sending
	// creds via the body instead of the Authorization header.
	if r.PostForm.Get("client_secret") != "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"title":"invalid_client: expected Basic auth, not POST body"}]}`)
		return
	}

	f.mu.Lock()
	f.tokenFetches++
	n := f.tokenFetches
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"access_token":"test-token-%d","token_type":"Bearer","expires_in":%d}`, n, f.tokenExpiresIn)
}

func (f *fakeMASAdmin) requireBearer(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer test-token-") {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

type fakeUserAttrs struct {
	Username      string     `json:"username"`
	CreatedAt     time.Time  `json:"created_at"`
	LockedAt      *time.Time `json:"locked_at"`
	DeactivatedAt *time.Time `json:"deactivated_at"`
}

type fakeEmailAttrs struct {
	CreatedAt time.Time `json:"created_at"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
}

type fakeResource[T any] struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes T      `json:"attributes"`
}

func writePage[T any](w http.ResponseWriter, data []fakeResource[T], hasNext bool) {
	resp := struct {
		Data  []fakeResource[T] `json:"data"`
		Links struct {
			Next string `json:"next,omitempty"`
		} `json:"links"`
	}{Data: data}
	if hasNext {
		resp.Links.Next = "has-more" // Client only checks presence, never parses this URL
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// paginate slices sorted (by id, ascending -- matching real MAS's UserFilter ordering) according
// to page[first]/page[after] query params, mirroring admin/params.rs's contract.
func paginate[T any](r *http.Request, ids []string, first int) (start, end int, hasNext bool) {
	if v := r.URL.Query().Get("page[first]"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			first = n
		}
	}
	start = 0
	if after := r.URL.Query().Get("page[after]"); after != "" {
		for i, id := range ids {
			if id == after {
				start = i + 1
				break
			}
		}
	}
	end = start + first
	if end > len(ids) {
		end = len(ids)
	}
	if start > len(ids) {
		start = len(ids)
	}
	hasNext = end < len(ids)
	return start, end, hasNext
}

func (f *fakeMASAdmin) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	sorted := append([]*fakeUser(nil), f.users...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].id < sorted[j].id })
	ids := make([]string, len(sorted))
	for i, u := range sorted {
		ids[i] = u.id
	}
	if f.cycleUsers && len(sorted) > 0 {
		u := sorted[0]
		writePage(w, []fakeResource[fakeUserAttrs]{{
			Type: "user", ID: u.id,
			Attributes: fakeUserAttrs{Username: u.username, CreatedAt: u.createdAt, LockedAt: u.lockedAt},
		}}, true)
		return
	}

	start, end, hasNext := paginate[fakeUserAttrs](r, ids, 10)

	data := make([]fakeResource[fakeUserAttrs], 0, end-start)
	for _, u := range sorted[start:end] {
		data = append(data, fakeResource[fakeUserAttrs]{
			Type: "user",
			ID:   u.id,
			Attributes: fakeUserAttrs{
				Username:  u.username,
				CreatedAt: u.createdAt,
				LockedAt:  u.lockedAt,
			},
		})
	}
	writePage(w, data, hasNext)
}

func (f *fakeMASAdmin) handleListEmails(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	type entry struct {
		id, userID, email string
	}
	var entries []entry
	i := 0
	filterUser := r.URL.Query().Get("filter[user]")
	for userID, email := range f.emails {
		if filterUser != "" && filterUser != userID {
			continue
		}
		entries = append(entries, entry{id: testULID(fmt.Sprintf("email-%04d", i)), userID: userID, email: email})
		i++
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })
	ids := make([]string, len(entries))
	for i, e := range entries {
		ids[i] = e.id
	}
	if f.cycleEmails && len(entries) > 0 {
		e := entries[0]
		writePage(w, []fakeResource[fakeEmailAttrs]{{
			Type: "user-email", ID: e.id,
			Attributes: fakeEmailAttrs{CreatedAt: time.Now().UTC(), UserID: e.userID, Email: e.email},
		}}, true)
		return
	}

	start, end, hasNext := paginate[fakeEmailAttrs](r, ids, 10)

	data := make([]fakeResource[fakeEmailAttrs], 0, end-start)
	for _, e := range entries[start:end] {
		data = append(data, fakeResource[fakeEmailAttrs]{
			Type: "user-email",
			ID:   e.id,
			Attributes: fakeEmailAttrs{
				CreatedAt: time.Now().UTC(),
				UserID:    e.userID,
				Email:     e.email,
			},
		})
	}
	writePage(w, data, hasNext)
}

func (f *fakeMASAdmin) handleLock(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	id := r.PathValue("id")

	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.id == id {
			if u.lockedAt == nil {
				now := time.Now().UTC()
				u.lockedAt = &now
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"data": map[string]any{
					"type": "user",
					"id":   u.id,
					"attributes": map[string]any{
						"username":   u.username,
						"created_at": u.createdAt,
						"locked_at":  u.lockedAt,
					},
				},
			})
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, `{"errors":[{"title":"User ID %s not found"}]}`, id)
}

func TestToken_BasicAuthCachedAcrossCalls(t *testing.T) {
	fake := newFakeMASAdmin("janitor-client", "s3cr3t")
	srv := fake.server()
	defer srv.Close()

	c := NewClient(srv.URL, "janitor-client", "s3cr3t")
	ctx := context.Background()

	if _, err := c.ListUsers(ctx); err != nil {
		t.Fatalf("first ListUsers: %v", err)
	}
	if _, err := c.ListUsers(ctx); err != nil {
		t.Fatalf("second ListUsers: %v", err)
	}

	if fake.tokenFetches != 1 {
		t.Errorf("tokenFetches = %d, want 1 (token should be cached across calls)", fake.tokenFetches)
	}
}

func TestToken_RefetchesNearExpiry(t *testing.T) {
	fake := newFakeMASAdmin("janitor-client", "s3cr3t")
	fake.tokenExpiresIn = 1 // well under tokenSafetyMargin, forces a refetch every call
	srv := fake.server()
	defer srv.Close()

	c := NewClient(srv.URL, "janitor-client", "s3cr3t")
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := c.ListUsers(ctx); err != nil {
			t.Fatalf("ListUsers call %d: %v", i, err)
		}
	}

	if fake.tokenFetches != 3 {
		t.Errorf("tokenFetches = %d, want 3 (a ~1s-TTL token should be refetched every call)", fake.tokenFetches)
	}
}

func TestToken_WrongCredentialsFails(t *testing.T) {
	fake := newFakeMASAdmin("janitor-client", "s3cr3t")
	srv := fake.server()
	defer srv.Close()

	c := NewClient(srv.URL, "janitor-client", "wrong-secret")
	if _, err := c.ListUsers(context.Background()); err == nil {
		t.Fatal("expected an error with the wrong client secret")
	}
}

func TestListUsers_Pagination(t *testing.T) {
	fake := newFakeMASAdmin("janitor-client", "s3cr3t")
	srv := fake.server()
	defer srv.Close()

	const n = 2*listPageSize + 7 // forces three pages at the client's fixed page size
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		fake.addUser(fmt.Sprintf("user-%05d", i), fmt.Sprintf("agent%05d", i), base.Add(time.Duration(i)*time.Minute), false)
	}

	c := NewClient(srv.URL, "janitor-client", "s3cr3t")
	got, err := c.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(got) != n {
		t.Fatalf("got %d users, want %d", len(got), n)
	}

	seen := make(map[string]bool, n)
	for _, u := range got {
		seen[u.ID] = true
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct user IDs, want %d (pagination must not duplicate or drop)", len(seen), n)
	}
}

func TestListUsers_RejectsCursorCycle(t *testing.T) {
	fake := newFakeMASAdmin("janitor-client", "s3cr3t")
	fake.cycleUsers = true
	fake.addUser("user-1", "agent", time.Now(), false)
	srv := fake.server()
	defer srv.Close()

	c := NewClient(srv.URL, "janitor-client", "s3cr3t")
	if _, err := c.ListUsers(context.Background()); err == nil || !strings.Contains(err.Error(), "cursor") {
		t.Fatalf("ListUsers error = %v, want cursor-cycle rejection", err)
	}
}

func TestListUserEmails(t *testing.T) {
	fake := newFakeMASAdmin("janitor-client", "s3cr3t")
	srv := fake.server()
	defer srv.Close()

	fake.addUser("user-1", "alice", time.Now(), false)
	fake.addUser("user-2", "bob-agent", time.Now(), false)
	fake.addEmail("user-1", "alice@example.com")

	c := NewClient(srv.URL, "janitor-client", "s3cr3t")
	got, err := c.ListUserEmails(context.Background())
	if err != nil {
		t.Fatalf("ListUserEmails: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d emails, want 1", len(got))
	}
	if got[0].UserID != testULID("user-1") || got[0].Email != "alice@example.com" {
		t.Errorf("got %+v, want user_id=%s email=alice@example.com", got[0], testULID("user-1"))
	}
}

func TestListUserEmails_RejectsCursorCycle(t *testing.T) {
	fake := newFakeMASAdmin("janitor-client", "s3cr3t")
	fake.cycleEmails = true
	fake.addEmail("user-1", "alice@example.com")
	srv := fake.server()
	defer srv.Close()

	c := NewClient(srv.URL, "janitor-client", "s3cr3t")
	if _, err := c.ListUserEmails(context.Background()); err == nil || !strings.Contains(err.Error(), "cursor") {
		t.Fatalf("ListUserEmails error = %v, want cursor-cycle rejection", err)
	}
}

func TestLockUser(t *testing.T) {
	fake := newFakeMASAdmin("janitor-client", "s3cr3t")
	srv := fake.server()
	defer srv.Close()

	fake.addUser("user-1", "stale-agent", time.Now().Add(-72*time.Hour), false)

	c := NewClient(srv.URL, "janitor-client", "s3cr3t")
	ctx := context.Background()

	err := c.LockUser(ctx, testULID("user-1"))
	if err != nil {
		t.Fatalf("LockUser: %v", err)
	}

	users, err := c.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers after lock: %v", err)
	}
	if len(users) != 1 || users[0].LockedAt == nil {
		t.Fatalf("expected user-1 to be locked, got %+v", users)
	}
}

func TestLockUser_NotFound(t *testing.T) {
	fake := newFakeMASAdmin("janitor-client", "s3cr3t")
	srv := fake.server()
	defer srv.Close()

	c := NewClient(srv.URL, "janitor-client", "s3cr3t")
	err := c.LockUser(context.Background(), testULID("no-such-user"))
	if err == nil {
		t.Fatal("expected an error locking an unknown user ID")
	}
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("error = %v, want errors.Is(..., ErrUserNotFound)", err)
	}
}

func TestMASFieldValidationRejectsAmbiguousIdentitiesAndOversizedTokens(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		max   int
		want  bool
	}{
		{name: "empty", value: "", max: maxMASIdentifierBytes, want: false},
		{name: "whitespace", value: "user id", max: maxMASIdentifierBytes, want: false},
		{name: "control", value: "user\n", max: maxMASIdentifierBytes, want: false},
		{name: "oversized", value: strings.Repeat("x", maxMASTokenBytes+1), max: maxMASTokenBytes, want: false},
		{name: "normal", value: "user-01", max: maxMASIdentifierBytes, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validMASField(test.value, test.max); got != test.want {
				t.Fatalf("validMASField(%q, %d) = %t, want %t", test.value, test.max, got, test.want)
			}
		})
	}
}

func TestMASIdentityValidationRequiresCanonicalULIDsAndUsernames(t *testing.T) {
	validID := testULID("valid-user")
	for _, test := range []struct {
		name  string
		value string
		valid bool
	}{
		{name: "canonical ULID", value: validID, valid: true},
		{name: "lowercase ULID", value: strings.ToLower(validID), valid: false},
		{name: "short ID", value: validID[:25], valid: false},
		{name: "overflowing ULID", value: "8" + validID[1:], valid: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validMASULID(test.value); got != test.valid {
				t.Fatalf("validMASULID(%q) = %t, want %t", test.value, got, test.valid)
			}
		})
	}
	for _, test := range []struct {
		name  string
		value string
		valid bool
	}{
		{name: "canonical username", value: "agent_01", valid: true},
		{name: "canonical plus username", value: "agent+01", valid: true},
		{name: "uppercase username", value: "Agent", valid: false},
		{name: "remote username", value: "agent:remote", valid: false},
		{name: "whitespace username", value: "agent name", valid: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validMASUsername(test.value); got != test.valid {
				t.Fatalf("validMASUsername(%q) = %t, want %t", test.value, got, test.valid)
			}
		})
	}
}

func TestValidMXIDBoundsTheCompleteIdentity(t *testing.T) {
	serverName := "stage.telecrypt.io"
	if !ValidMXID(strings.Repeat("a", 255-len("@:"+serverName)), serverName) {
		t.Fatal("ValidMXID rejected the exact 255-byte identity boundary")
	}
	if ValidMXID(strings.Repeat("a", 256-len("@:"+serverName)), serverName) {
		t.Fatal("ValidMXID accepted an oversized complete identity")
	}
	if ValidMXID("agent+01", "") {
		t.Fatal("ValidMXID accepted an empty server name")
	}
}
