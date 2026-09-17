// Package healthcheck probes a service's local HTTP health endpoint.
package healthcheck

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/httpdiag"
)

// Check follows Cashier's probe contract: HTTP 200, no redirects, two-second timeout.
func Check(endpoint string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		body, readErr, closeErr := httpdiag.ReadAndClose(resp.Body)
		return httpdiag.NewResponseError("health check", resp.StatusCode, body, readErr, closeErr)
	}
	readErr, closeErr := httpdiag.DrainAndClose(resp.Body)
	return errors.Join(readErr, closeErr)
}
