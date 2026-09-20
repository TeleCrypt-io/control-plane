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
		if r.Method != http.MethodGet || r.URL.Path != "/subscriptions" || r.URL.Query().Get("page_size") != "100" || r.URL.Query().Get("page_number") != "0" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer read-only-key" {
			t.Fatalf("authorization = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{{"subscription_id": "sub-1", "status": "on_hold", "product_id": "prod-1"}}})
	}))
	defer server.Close()
	got, err := NewDodoReader(server.URL, "read-only-key").Subscriptions(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if calls != 1 || len(got) != 1 || got[0].Status != "on_hold" || got[0].ProviderProductID != "prod-1" {
		t.Fatalf("calls=%d subscriptions=%#v", calls, got)
	}
}

func TestDodoReaderFetchesEverySubscriptionPage(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		page := r.URL.Query().Get("page_number")
		if page == "0" {
			items := make([]map[string]string, 100)
			for i := range items {
				items[i] = map[string]string{"subscription_id": "sub-" + string(rune('a'+i%26)), "status": "active"}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{{"subscription_id": "sub-last", "status": "cancelled"}}})
	}))
	defer server.Close()
	got, err := NewDodoReader(server.URL, "key").Subscriptions(context.Background())
	if err != nil {
		t.Fatalf("Subscriptions: %v", err)
	}
	if calls != 2 || len(got) != 101 || got[len(got)-1].SubscriptionID != "sub-last" {
		t.Fatalf("calls=%d subscriptions=%d last=%#v", calls, len(got), got[len(got)-1])
	}
}

func TestDodoReaderDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.RedirectHandler("/subscriptions", http.StatusFound))
	defer server.Close()
	if _, err := NewDodoReader(server.URL, "key").Subscriptions(context.Background()); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("Reconcile error = %v, want redirect error", err)
	}
}
