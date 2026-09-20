package synapseadmin

import (
	"context"
	"encoding/json"
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
