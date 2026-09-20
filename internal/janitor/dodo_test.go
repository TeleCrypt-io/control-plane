package janitor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDodoReaderUsesOneReadOnlyRequest(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/subscriptions" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer read-only-key" {
			t.Fatalf("authorization = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{{"subscription_id": "sub-1", "status": "on_hold"}}})
	}))
	defer server.Close()
	got, err := NewDodoReader(server.URL, "read-only-key").Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if calls != 1 || len(got) != 1 || got[0].Kind != "on_hold" {
		t.Fatalf("calls=%d discrepancies=%#v", calls, got)
	}
}

func TestDodoReaderDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.RedirectHandler("/subscriptions", http.StatusFound))
	defer server.Close()
	if _, err := NewDodoReader(server.URL, "key").Reconcile(context.Background()); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("Reconcile error = %v, want redirect error", err)
	}
}
