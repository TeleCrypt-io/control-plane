package plan

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestHTTPCashierClientUsesPrivateMXIDHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/internal/cashier/plan/state" {
			http.Error(w, "wrong route", http.StatusBadRequest)
			return
		}
		if got, want := r.Header.Get(planMXIDHeader), "@alice:telecrypt.io"; got != want {
			t.Errorf("Cashier MXID header = %q, want %q", got, want)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Cashier Authorization header = %q, want empty", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"plan":{"subscription_status":"active","member_limit":2},"members":[{"mxid":"@alice:telecrypt.io"}]}`))
	}))
	defer server.Close()

	client, err := NewHTTPCashierClient(server.URL, server.Client())
	if err != nil {
		t.Fatalf("new HTTP Cashier client: %v", err)
	}
	state, err := client.PlanState(t.Context(), Principal{MXID: "@alice:telecrypt.io"})
	if err != nil {
		t.Fatalf("PlanState: %v", err)
	}
	if state.Plan == nil || state.Plan.MemberLimit != 2 || len(state.Members) != 1 {
		t.Fatalf("PlanState = %#v, want one private plan member", state)
	}
}

func TestHTTPCashierClientCanonicalizesEscapedMemberRemovalPath(t *testing.T) {
	const pathPrefix = "/internal/cashier/team/members/"
	cases := []struct {
		name string
		mxid string
	}{
		{name: "ordinary", mxid: "@alice:telecrypt.io"},
		{name: "slash-containing", mxid: "@bot/one:telecrypt.io"},
		{name: "unicode", mxid: "@böt:telecrypt.io"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.EscapedPath(), pathPrefix) || !strings.HasSuffix(r.URL.EscapedPath(), "/remove") {
			http.Error(w, "wrong escaped route", http.StatusBadRequest)
			return
		}
		if r.Header.Get(planMXIDHeader) != "@admin:telecrypt.io" {
			http.Error(w, "wrong principal", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewHTTPCashierClient(server.URL, server.Client())
	if err != nil {
		t.Fatalf("new HTTP Cashier client: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := client.RemoveMember(t.Context(), Principal{MXID: "@admin:telecrypt.io"}, tc.mxid); err != nil {
				t.Fatalf("RemoveMember(%q): %v", tc.mxid, err)
			}
			if !strings.Contains(pathPrefix+url.PathEscape(tc.mxid)+"/remove", "/remove") {
				t.Fatal("test route did not include removal action")
			}
		})
	}
}

func TestHTTPCashierClientReturnsBusinessStatus(t *testing.T) {
	const secret = "cashier-client-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "provider detail access_token="+secret+" tail", http.StatusConflict)
	}))
	defer server.Close()
	client, err := NewHTTPCashierClient(server.URL, server.Client())
	if err != nil {
		t.Fatalf("new HTTP Cashier client: %v", err)
	}
	err = client.AttachMember(t.Context(), Principal{MXID: "@alice:telecrypt.io"}, "@bot:telecrypt.io")
	var cashierError *CashierError
	if !errors.As(err, &cashierError) || cashierError.StatusCode != http.StatusConflict {
		t.Fatalf("AttachMember error = %#v, want CashierError 409", err)
	}
	if !strings.Contains(cashierError.Message, "provider detail access_token="+secret+" tail") {
		t.Fatalf("Cashier error message = %q, want complete raw body", cashierError.Message)
	}
}

func TestHTTPCashierClientPreservesResponseCloseFailure(t *testing.T) {
	closeErr := errors.New("Cashier response close failed")
	client, err := NewHTTPCashierClient("http://cashier.example", &http.Client{})
	if err != nil {
		t.Fatalf("new HTTP Cashier client: %v", err)
	}
	client.httpClient.Transport = cashierRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusConflict,
			Body:       &cashierResponseBody{reader: strings.NewReader("no seats"), closeErr: closeErr},
		}, nil
	})
	err = client.AttachMember(context.Background(), Principal{MXID: "@alice:telecrypt.io"}, "@bot:telecrypt.io")
	var cashierError *CashierError
	if !errors.As(err, &cashierError) || !errors.Is(err, closeErr) {
		t.Fatalf("Cashier response error = %v, want CashierError with close failure", err)
	}
}

func TestHTTPCashierClientDoesNotUseAmbientProxy(t *testing.T) {
	client, err := NewHTTPCashierClient("http://cashier.example", nil)
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

func TestHTTPCashierClientRejectsRedirects(t *testing.T) {
	calls := 0
	httpClient := &http.Client{Transport: cashierRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Header:     http.Header{"Location": {"http://attacker.example/steal"}},
			Body:       io.NopCloser(strings.NewReader("redirect")),
			Request:    r,
		}, nil
	})}
	client, err := NewHTTPCashierClient("http://cashier.example", httpClient)
	if err != nil {
		t.Fatalf("new HTTP Cashier client: %v", err)
	}
	if err := client.AttachMember(t.Context(), Principal{MXID: "@alice:telecrypt.io"}, "@bot:telecrypt.io"); err == nil {
		t.Fatal("AttachMember unexpectedly followed redirect")
	}
	if calls != 1 {
		t.Fatalf("transport calls = %d, want 1", calls)
	}
}
