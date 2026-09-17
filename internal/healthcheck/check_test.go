package healthcheck

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckRequiresOKWithoutFollowingRedirects(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable, http.StatusFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/health" {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.Header().Set("Location", "/other")
				w.WriteHeader(status)
			}))
			defer server.Close()
			err := Check(server.URL + "/health")
			if (err == nil) != (status == http.StatusOK) {
				t.Fatalf("status %d: error = %v", status, err)
			}
			if calls != 1 {
				t.Fatalf("requests = %d, want 1", calls)
			}
		})
	}
}
