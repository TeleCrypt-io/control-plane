//go:build integration

package masreg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const disposableConfirmation = "YES"

// TestRegisterAndAuthorizeDeviceDisposableMAS is deliberately excluded from the default test
// suite. It creates a real account, a dynamic OAuth client, and a Matrix device, so it must only
// run against a disposable MAS/Synapse deployment explicitly named by the operator. Release
// acceptance must run it against the exact prebuilt MAS 1.23 image: the strict completion-path
// allowlist in client.go is fixture-observed, not independently documented by upstream MAS.
func TestRegisterAndAuthorizeDeviceDisposableMAS(t *testing.T) {
	masBase := requiredIntegrationEnv(t, "MASREG_INTEGRATION_MAS_BASE_URL")
	matrixOrigin := requiredIntegrationEnv(t, "MASREG_INTEGRATION_MATRIX_ORIGIN")
	if got := os.Getenv("MASREG_INTEGRATION_DISPOSABLE"); got != disposableConfirmation {
		t.Fatalf("MASREG_INTEGRATION_DISPOSABLE must be %q; this test mutates the configured MAS", disposableConfirmation)
	}
	if err := validateIntegrationURLs(masBase, matrixOrigin); err != nil {
		t.Fatalf("invalid disposable MAS integration URLs: %v", err)
	}

	suffix := randomHex(t, 16)
	username := "tcint" + suffix[:20]
	password := "tc-test-" + randomHex(t, 24)
	deviceID := "TCINT" + strings.ToUpper(suffix)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tokens, err := NewClient(masBase).RegisterAndAuthorizeDevice(ctx, username, password, deviceID, matrixOrigin)
	if err != nil {
		t.Fatalf("RegisterAndAuthorizeDevice against disposable MAS: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.ClientID == "" {
		t.Fatalf("MAS returned incomplete OAuth metadata: access=%t refresh=%t client_id=%t", tokens.AccessToken != "", tokens.RefreshToken != "", tokens.ClientID != "")
	}
	if tokens.ExpiresIn <= 0 {
		t.Fatalf("MAS returned non-positive token expiry: %d", tokens.ExpiresIn)
	}
	expectedBase := strings.TrimRight(masBase, "/")
	if tokens.Issuer != expectedBase+"/" || tokens.TokenEndpoint != expectedBase+"/oauth2/token" {
		t.Fatalf("MAS returned issuer/token endpoint %q / %q, want %q / %q", tokens.Issuer, tokens.TokenEndpoint, expectedBase+"/", expectedBase+"/oauth2/token")
	}

	// RegisterAndAuthorizeDevice validates this internally; repeat the public whoami assertion
	// here so this integration test records the device metadata bound to the returned token too.
	userID, returnedDeviceID, err := (&session{baseURL: strings.TrimRight(masBase, "/"), publicHTTPClient: newPublicHTTPClient()}).whoAmI(ctx, matrixOrigin, tokens.AccessToken)
	if err != nil {
		t.Fatalf("validate disposable-MAS token with Matrix whoami: %v", err)
	}
	if userID != tokens.UserID || !strings.Contains(userID, username) {
		t.Fatalf("MAS returned user metadata %q, want user %q containing generated username", userID, username)
	}
	if returnedDeviceID != deviceID {
		t.Fatalf("Matrix returned device ID %q, want generated device ID %q", returnedDeviceID, deviceID)
	}
}

func requiredIntegrationEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s is required when the integration build tag is selected", name)
	}
	return value
}

func validateIntegrationURLs(masRaw, matrixRaw string) error {
	mas, err := parseIntegrationURL("MASREG_INTEGRATION_MAS_BASE_URL", masRaw)
	if err != nil {
		return err
	}
	matrix, err := parseIntegrationURL("MASREG_INTEGRATION_MATRIX_ORIGIN", matrixRaw)
	if err != nil {
		return err
	}
	if mas.Scheme != "http" || matrix.Scheme != "http" {
		return fmt.Errorf("both URLs must use http")
	}
	if !isLoopbackHost(mas) || !isLoopbackHost(matrix) {
		return fmt.Errorf("both URLs must use loopback hosts: localhost, 127.0.0.1, or ::1")
	}
	if !sameHTTPOrigin(mas, matrix) {
		return fmt.Errorf("MAS base URL and Matrix origin must have the same origin")
	}
	if matrix.Path != "" && matrix.Path != "/" {
		return fmt.Errorf("Matrix origin must have no path other than /")
	}
	if mas.EscapedPath() != "" && mas.EscapedPath() != "/" {
		return fmt.Errorf("MAS base URL must be the origin without a path")
	}
	return nil
}

func parseIntegrationURL(name, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%s must be an absolute URL without credentials, query, or fragment: %q", name, raw)
	}
	return u, nil
}

func isLoopbackHost(u *url.URL) bool {
	switch strings.ToLower(u.Hostname()) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func sameHTTPOrigin(left, right *url.URL) bool {
	if !strings.EqualFold(left.Scheme, right.Scheme) ||
		!strings.EqualFold(left.Hostname(), right.Hostname()) {
		return false
	}
	return effectiveHTTPPort(left) == effectiveHTTPPort(right)
}

func effectiveHTTPPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	return "80"
}

func TestValidateIntegrationURLs(t *testing.T) {
	tests := []struct {
		name      string
		masBase   string
		matrix    string
		wantError string
	}{
		{
			name:    "loopback IPv4 with root MAS path",
			masBase: "http://127.0.0.1:8008/",
			matrix:  "http://127.0.0.1:8008/",
		},
		{
			name:    "loopback hostname with default port",
			masBase: "http://localhost",
			matrix:  "http://localhost",
		},
		{
			name:      "HTTPS is rejected",
			masBase:   "https://127.0.0.1:8008",
			matrix:    "https://127.0.0.1:8008",
			wantError: "http",
		},
		{
			name:      "non-loopback host is rejected",
			masBase:   "http://mas:8008",
			matrix:    "http://mas:8008",
			wantError: "loopback",
		},
		{
			name:      "different origins are rejected",
			masBase:   "http://127.0.0.1:8008",
			matrix:    "http://localhost:8008",
			wantError: "same origin",
		},
		{
			name:      "different ports are rejected",
			masBase:   "http://127.0.0.1:8008",
			matrix:    "http://127.0.0.1:8009",
			wantError: "same origin",
		},
		{
			name:      "Matrix path is rejected",
			masBase:   "http://[::1]:8008",
			matrix:    "http://[::1]:8008/matrix",
			wantError: "Matrix origin",
		},
		{
			name:      "MAS path is rejected",
			masBase:   "http://127.0.0.1:8008/auth/",
			matrix:    "http://127.0.0.1:8008",
			wantError: "MAS base URL",
		},
		{
			name:      "encoded MAS path is rejected",
			masBase:   "http://127.0.0.1:8008/%61uth",
			matrix:    "http://127.0.0.1:8008",
			wantError: "MAS base URL",
		},
		{
			name:      "query is rejected",
			masBase:   "http://127.0.0.1:8008?debug=1",
			matrix:    "http://127.0.0.1:8008",
			wantError: "without credentials",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateIntegrationURLs(test.masBase, test.matrix)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("validateIntegrationURLs() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validateIntegrationURLs() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func randomHex(t *testing.T, bytes int) string {
	t.Helper()
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generate integration identity: %v", err)
	}
	return hex.EncodeToString(buf)
}
