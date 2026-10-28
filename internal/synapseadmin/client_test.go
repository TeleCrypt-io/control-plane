package synapseadmin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSuspendUserUsesNativeAdminEndpointAndBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, "/_synapse/admin/v1/suspend/") {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer synapse-secret" {
			t.Fatalf("authorization = %q", got)
		}
		var body map[string]bool
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if !body["suspend"] {
			t.Fatalf("body = %#v", body)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := NewClient(server.URL, "synapse-secret").SuspendUser(context.Background(), "@alice:example.test", true); err != nil {
		t.Fatalf("SuspendUser: %v", err)
	}
}

func TestSuspendUserRejectsRedirects(t *testing.T) {
	redirect := httptest.NewServer(http.RedirectHandler("/next", http.StatusFound))
	defer redirect.Close()
	if err := NewClient(redirect.URL, "token").SuspendUser(context.Background(), "@alice:example.test", true); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("SuspendUser error = %v, want redirect error", err)
	}
}

func TestDeleteAllMediaBatchesAndInterruptedRetry(t *testing.T) {
	for _, count := range []int{0, 205} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			remaining, calls, failed := count, 0, false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodDelete || r.URL.Query().Get("from") != "0" || r.URL.Query().Get("limit") != "100" {
					t.Error("incorrect deletion request")
				}
				if count > 0 && calls == 2 && !failed {
					failed = true
					http.Error(w, "interrupted", 503)
					return
				}
				n := min(100, remaining)
				ids := make([]string, n)
				for i := range ids {
					ids[i] = fmt.Sprintf("media-%d", remaining-i)
				}
				remaining -= n
				json.NewEncoder(w).Encode(map[string]any{"deleted_media": ids, "total": n})
			}))
			defer server.Close()
			client := NewClient(server.URL, "token")
			err := client.DeleteAllMedia(context.Background(), "@user:test")
			if count > 0 {
				if err == nil || remaining != 105 {
					t.Fatalf("interruption: remaining=%d err=%v", remaining, err)
				}
				err = client.DeleteAllMedia(context.Background(), "@user:test")
			}
			if err != nil || remaining != 0 {
				t.Fatalf("remaining=%d err=%v", remaining, err)
			}
			want := 1
			if count > 0 {
				want = 5
			}
			if calls != want {
				t.Fatalf("calls=%d want=%d", calls, want)
			}
		})
	}
}
