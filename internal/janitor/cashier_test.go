package janitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCashierClientCallsPrivateLifecycleAndReportingOperations(t *testing.T) {
	createdAt := time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC)
	cursor := DigestCursor{CreatedAt: createdAt, EmailID: "01J00000000000000000000001"}
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "POST /internal/cashier/janitor/account-sync":
			var body accountSyncRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.MXID != "@alice:example.test" || !body.CreatedAt.Equal(createdAt) {
				http.Error(w, fmt.Sprintf("unexpected sync request: %#v (%v)", body, err), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "GET /internal/cashier/janitor/actions":
			_, _ = w.Write([]byte(`[{"mxid":"@alice:example.test","action":"suspend","due_at":"2026-09-22T03:00:00Z"}]`))
		case "POST /internal/cashier/janitor/suspend", "POST /internal/cashier/janitor/start-removal", "POST /internal/cashier/janitor/finish-removal":
			var body accountRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.MXID != "@alice:example.test" {
				http.Error(w, "unexpected account action", http.StatusBadRequest)
				return
			}
			applied := !strings.HasSuffix(r.URL.Path, "/start-removal")
			_ = json.NewEncoder(w).Encode(actionResult{Applied: applied})
		case "GET /internal/cashier/janitor/subscriptions":
			_, _ = w.Write([]byte(`[{"subscription_id":"sub-1","status":"active","provider_product_id":"team","team_id":"team-1"}]`))
		case "GET /internal/cashier/janitor/digest-cursor":
			_ = json.NewEncoder(w).Encode(cursorResult{Found: true, Cursor: &cursor})
		case "PUT /internal/cashier/janitor/digest-cursor":
			var got DigestCursor
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil || got != cursor {
				http.Error(w, "unexpected cursor", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := &CashierClient{baseURL: server.URL + "/internal/cashier/janitor", http: server.Client()}
	ctx := context.Background()

	if err := client.SyncLifecycleAccount(ctx, "@alice:example.test", createdAt); err != nil {
		t.Fatalf("SyncLifecycleAccount: %v", err)
	}
	actions, err := client.LifecycleActions(ctx)
	if err != nil || len(actions) != 1 || actions[0].Action != "suspend" || actions[0].MXID != "@alice:example.test" {
		t.Fatalf("LifecycleActions = %#v, %v", actions, err)
	}
	if applied, err := client.ExecuteSuspension(ctx, "@alice:example.test"); err != nil || !applied {
		t.Fatalf("ExecuteSuspension = %v, %v", applied, err)
	}
	if applied, err := client.StartRemoval(ctx, "@alice:example.test"); err != nil || applied {
		t.Fatalf("StartRemoval = %v, %v", applied, err)
	}
	if applied, err := client.FinishRemoval(ctx, "@alice:example.test"); err != nil || !applied {
		t.Fatalf("FinishRemoval = %v, %v", applied, err)
	}
	subscriptions, err := client.ProviderSubscriptionSnapshot(ctx)
	if err != nil || len(subscriptions) != 1 || subscriptions[0].TeamID != "team-1" {
		t.Fatalf("ProviderSubscriptionSnapshot = %#v, %v", subscriptions, err)
	}
	gotCursor, found, err := client.JanitorDigestCursor(ctx)
	if err != nil || !found || gotCursor != cursor {
		t.Fatalf("JanitorDigestCursor = %#v, %v, %v", gotCursor, found, err)
	}
	if err := client.SetJanitorDigestCursor(ctx, cursor); err != nil {
		t.Fatalf("SetJanitorDigestCursor: %v", err)
	}
	want := []string{
		"POST /internal/cashier/janitor/account-sync",
		"GET /internal/cashier/janitor/actions",
		"POST /internal/cashier/janitor/suspend",
		"POST /internal/cashier/janitor/start-removal",
		"POST /internal/cashier/janitor/finish-removal",
		"GET /internal/cashier/janitor/subscriptions",
		"GET /internal/cashier/janitor/digest-cursor",
		"PUT /internal/cashier/janitor/digest-cursor",
	}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("requests = %#v, want %#v", seen, want)
	}
}

func TestCashierClientRetainsCompleteErrorResponse(t *testing.T) {
	const response = "database query failed: SQLSTATE 42P08 parameter $2\nfull diagnostic text"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()
	client := &CashierClient{baseURL: server.URL + "/internal/cashier/janitor", http: server.Client()}
	_, err := client.LifecycleActions(context.Background())
	if err == nil || !strings.Contains(err.Error(), "full diagnostic text") || !strings.Contains(err.Error(), "SQLSTATE 42P08") {
		t.Fatalf("error = %v, want complete response body %q", err, response)
	}
}
