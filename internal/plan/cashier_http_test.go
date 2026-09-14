package plan

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

type cashierResponseBody struct {
	reader   io.Reader
	closeErr error
}

func (b *cashierResponseBody) Read(p []byte) (int, error) { return b.reader.Read(p) }
func (b *cashierResponseBody) Close() error               { return b.closeErr }

type cashierRoundTripFunc func(*http.Request) (*http.Response, error)

func (f cashierRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTPCashierClientPreservesPrivatePlanCreationProtocol(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/teams" {
			http.Error(w, "wrong route", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "{}" {
			http.Error(w, "wrong body", http.StatusBadRequest)
			return
		}
		claims := verifyPlanJWS(t, r.Header.Get("Authorization"), public)
		if claims.Subject != "@alice:telecrypt.io" || claims.Audience != planAssertionAudience ||
			claims.Method != r.Method || claims.Path != r.URL.Path ||
			claims.RequestID != "b3987ed2-51a4-4b04-b5f5-b915683d0cf5" {
			http.Error(w, "wrong claims", http.StatusUnauthorized)
			return
		}
		sum := sha256.Sum256(body)
		if claims.BodySHA256 != base64.RawURLEncoding.EncodeToString(sum[:]) || r.Header.Get(planRequestIDHeader) != claims.RequestID {
			http.Error(w, "unbound request", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewHTTPCashierClient(server.URL, base64.RawURLEncoding.EncodeToString(private), server.Client())
	if err != nil {
		t.Fatalf("new HTTP Cashier client: %v", err)
	}
	if err := client.CreatePlan(t.Context(), Principal{MXID: "@alice:telecrypt.io"}, "b3987ed2-51a4-4b04-b5f5-b915683d0cf5"); err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
}

func TestHTTPCashierClientReadsPrivatePlanState(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/internal/v1/plan-state" {
			http.Error(w, "wrong route", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"plan":{"subscription_status":"active","paid_seats":2},"seats":[{"mxid":"@alice:telecrypt.io"}]}`))
	}))
	defer server.Close()

	client, err := NewHTTPCashierClient(server.URL, base64.RawURLEncoding.EncodeToString(private), server.Client())
	if err != nil {
		t.Fatalf("new HTTP Cashier client: %v", err)
	}
	state, err := client.PlanState(t.Context(), Principal{MXID: "@alice:telecrypt.io"})
	if err != nil {
		t.Fatalf("PlanState: %v", err)
	}
	if state.Plan == nil || state.Plan.PaidSeats != 2 {
		t.Fatalf("PlanState plan = %#v, want private plan", state.Plan)
	}
	if len(state.Seats) != 1 || state.Seats[0].MXID != "@alice:telecrypt.io" {
		t.Fatalf("PlanState seats = %#v", state.Seats)
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal PlanState: %v", err)
	}
	if !strings.Contains(string(encoded), `"plan"`) {
		t.Fatalf("owned PlanState JSON = %s, want plan key", encoded)
	}
}

func TestHTTPCashierClientCanonicalizesEscapedSeatDeletePath(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	const pathPrefix = "/internal/v1/team/seats/"
	cases := []struct {
		name      string
		mxid      string
		requestID string
	}{
		{name: "ordinary", mxid: "@alice:telecrypt.io", requestID: "b3987ed2-51a4-4b04-b5f5-b915683d0cf5"},
		{name: "slash-containing", mxid: "@bot/one:telecrypt.io", requestID: "5c8c6d1b-e3a1-4d5a-9d9e-6b9f9bcd2f34"},
		{name: "unicode", mxid: "@böt:telecrypt.io", requestID: "c1a1eb4f-4ac7-4b9e-bf8a-9f4d2b3c6e71"},
	}
	wants := make(map[string]struct {
		path      string
		requestID string
	})
	for _, tc := range cases {
		escapedPath := pathPrefix + url.PathEscape(tc.mxid)
		wants[escapedPath] = struct {
			path      string
			requestID string
		}{path: escapedPath, requestID: tc.requestID}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want, ok := wants[r.URL.EscapedPath()]
		if !ok || r.Method != http.MethodDelete {
			http.Error(w, "wrong escaped route", http.StatusBadRequest)
			return
		}
		claims := verifyPlanJWS(t, r.Header.Get("Authorization"), private.Public().(ed25519.PublicKey))
		if claims.Subject != "@admin:telecrypt.io" || claims.Audience != planAssertionAudience ||
			claims.Method != r.Method || claims.Path != want.path || claims.Path != r.URL.EscapedPath() ||
			r.Header.Get(planRequestIDHeader) != want.requestID || claims.RequestID != want.requestID {
			http.Error(w, "wrong claims", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewHTTPCashierClient(server.URL, base64.RawURLEncoding.EncodeToString(private), server.Client())
	if err != nil {
		t.Fatalf("new HTTP Cashier client: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := client.RemoveSeat(t.Context(), Principal{MXID: "@admin:telecrypt.io"}, tc.requestID, tc.mxid); err != nil {
				t.Fatalf("RemoveSeat(%q): %v", tc.mxid, err)
			}
		})
	}
}

func TestHTTPCashierClientReturnsBusinessStatus(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	const secret = "cashier-client-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "provider detail access_token="+secret+" tail", http.StatusConflict)
	}))
	defer server.Close()
	client, err := NewHTTPCashierClient(server.URL, base64.RawURLEncoding.EncodeToString(private), server.Client())
	if err != nil {
		t.Fatalf("new HTTP Cashier client: %v", err)
	}
	err = client.AttachSeat(t.Context(), Principal{MXID: "@alice:telecrypt.io"}, "b3987ed2-51a4-4b04-b5f5-b915683d0cf5", "@bot:telecrypt.io")
	var cashierError *CashierError
	if !errors.As(err, &cashierError) || cashierError.StatusCode != http.StatusConflict {
		t.Fatalf("AttachSeat error = %#v, want CashierError 409", err)
	}
	if !strings.Contains(cashierError.Message, "provider detail access_token="+secret+" tail") {
		t.Fatalf("Cashier error message = %q, want complete raw body", cashierError.Message)
	}
}

func TestHTTPCashierClientPreservesResponseCloseFailure(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	closeErr := errors.New("Cashier response close failed")
	client, err := NewHTTPCashierClient("http://cashier.example", base64.RawURLEncoding.EncodeToString(private), &http.Client{})
	if err != nil {
		t.Fatalf("new HTTP Cashier client: %v", err)
	}
	client.httpClient.Transport = cashierRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusConflict,
			Body:       &cashierResponseBody{reader: strings.NewReader("no seats"), closeErr: closeErr},
		}, nil
	})
	err = client.AttachSeat(context.Background(), Principal{MXID: "@alice:telecrypt.io"}, "b3987ed2-51a4-4b04-b5f5-b915683d0cf5", "@bot:telecrypt.io")
	var cashierError *CashierError
	if !errors.As(err, &cashierError) || !errors.Is(err, closeErr) {
		t.Fatalf("Cashier response error = %v, want CashierError with close failure", err)
	}
}

func TestHTTPCashierClientCreatePlanResponseContract(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	for _, tc := range []struct {
		name      string
		status    int
		body      string
		wantError bool
	}{
		{name: "created", status: http.StatusCreated},
		{name: "idempotent replay", status: http.StatusNoContent},
		{name: "wrong success status", status: http.StatusOK, wantError: true},
		{name: "unexpected status", status: http.StatusAccepted, wantError: true},
		{name: "created with unexpected body", status: http.StatusCreated, body: "unexpected", wantError: true},
		{name: "idempotent replay with unexpected body", status: http.StatusNoContent, body: "unexpected", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/teams" {
					t.Errorf("request = %s %s, want POST /internal/v1/teams", r.Method, r.URL.Path)
				}
				return &http.Response{
					StatusCode: tc.status,
					Body:       io.NopCloser(strings.NewReader(tc.body)),
					Header:     make(http.Header),
					Request:    r,
				}, nil
			})}
			client, err := NewHTTPCashierClient("http://cashier.example", base64.RawURLEncoding.EncodeToString(private), httpClient)
			if err != nil {
				t.Fatalf("new HTTP Cashier client: %v", err)
			}
			err = client.CreatePlan(t.Context(), Principal{MXID: "@alice:telecrypt.io"}, "b3987ed2-51a4-4b04-b5f5-b915683d0cf5")
			if (err != nil) != tc.wantError {
				t.Fatalf("CreatePlan error = %v, wantError = %t", err, tc.wantError)
			}
		})
	}
}

func TestHTTPCashierClientOtherMutationsRejectCreateStatus(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/team/seats" {
			t.Errorf("request = %s %s, want POST /internal/v1/team/seats", r.Method, r.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})}
	client, err := NewHTTPCashierClient("http://cashier.example", base64.RawURLEncoding.EncodeToString(private), httpClient)
	if err != nil {
		t.Fatalf("new HTTP Cashier client: %v", err)
	}
	err = client.AttachSeat(t.Context(), Principal{MXID: "@alice:telecrypt.io"}, "b3987ed2-51a4-4b04-b5f5-b915683d0cf5", "@bot:telecrypt.io")
	var cashierError *CashierError
	if !errors.As(err, &cashierError) || cashierError.StatusCode != http.StatusCreated {
		t.Fatalf("AttachSeat error = %#v, want CashierError 201", err)
	}
}

func TestHTTPCashierClientRejectsCrossOriginRedirects(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			calls := 0
			httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{
					StatusCode: status,
					Header:     http.Header{"Location": {"http://attacker.example/steal"}},
					Body:       io.NopCloser(strings.NewReader("redirect")),
					Request:    r,
				}, nil
			})}
			client, err := NewHTTPCashierClient("http://cashier.example", base64.RawURLEncoding.EncodeToString(private), httpClient)
			if err != nil {
				t.Fatalf("new HTTP Cashier client: %v", err)
			}
			err = client.AttachSeat(t.Context(), Principal{MXID: "@alice:telecrypt.io"}, "b3987ed2-51a4-4b04-b5f5-b915683d0cf5", "@bot:telecrypt.io")
			if err == nil {
				t.Fatal("AttachSeat unexpectedly followed redirect")
			}
			if calls != 1 {
				t.Fatalf("transport calls = %d, want 1", calls)
			}
		})
	}
}

func TestHTTPCashierClientDoesNotUseAmbientProxy(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	client, err := NewHTTPCashierClient("http://cashier.example", base64.RawURLEncoding.EncodeToString(private), nil)
	if err != nil {
		t.Fatalf("NewHTTPCashierClient: %v", err)
	}
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Cashier transport = %T, want *http.Transport", client.httpClient.Transport)
	}
	if transport.Proxy != nil {
		t.Fatalf("Cashier transport proxy is enabled")
	}
}

func TestHTTPCashierClientDoesNotLeakCredentialsAcrossRedirect(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
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

			client, err := NewHTTPCashierClient(redirector.URL, base64.RawURLEncoding.EncodeToString(private), nil)
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodGet, redirector.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer signed-assertion")
			if _, err := client.httpClient.Do(req); err == nil {
				t.Fatal("Cashier client followed redirect")
			}
			if targetCalls != 0 {
				t.Fatalf("redirect target calls = %d, want 0", targetCalls)
			}
		})
	}
}

func verifyPlanJWS(t *testing.T, authorization string, public ed25519.PublicKey) planAssertion {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(authorization, "Bearer "), ".")
	if len(parts) != 3 || !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), mustDecode(t, parts[2])) {
		t.Fatal("Cashier Authorization is not a valid EdDSA JWS")
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	if err := json.Unmarshal(mustDecode(t, parts[0]), &header); err != nil || header.Algorithm != "EdDSA" || header.Type != "JWT" {
		t.Fatalf("Cashier Authorization has unexpected JWS header: %#v, %v", header, err)
	}
	var claims planAssertion
	if err := json.Unmarshal(mustDecode(t, parts[1]), &claims); err != nil {
		t.Fatalf("decode JWS claims: %v", err)
	}
	return claims
}

type planAssertion struct {
	Subject    string `json:"sub"`
	Audience   string `json:"aud"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	RequestID  string `json:"request_id"`
	BodySHA256 string `json:"body_sha256"`
}

func mustDecode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return decoded
}
