package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

const (
	testPlanClientID    = "01J00000000000000000000000"
	testJanitorClientID = "01J00000000000000000000001"
)

func testPlanPrivateKey() string {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed))
}

func setRequiredPlanEnv(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"SERVER_NAME":                "example.invalid",
		"BILLING_ENVIRONMENT":        "test",
		"MAS_OIDC_CLIENT_ID":         testPlanClientID,
		"MAS_ADMIN_CLIENT_ID":        testPlanClientID,
		"MAS_ADMIN_CLIENT_SECRET":    "admin-test-secret",
		"MAS_OIDC_CLIENT_SECRET":     "test-secret",
		"PLAN_SESSION_KEY":           strings.Repeat("s", 32),
		"PLAN_ASSERTION_PRIVATE_KEY": testPlanPrivateKey(),
	} {
		t.Setenv(key, value)
	}
}

func setRequiredJanitorEnv(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"MAS_ADMIN_CLIENT_ID":     testJanitorClientID,
		"MAS_ADMIN_CLIENT_SECRET": "secret",
		"JANITOR_DB_URL":          "postgres://janitor:secret@db/database",
		"SERVER_NAME":             "example.invalid",
		"BILLING_ENVIRONMENT":     "test",
		"SMTP_HOST":               "smtp.example.test",
		"SMTP_USERNAME":           "janitor@example.test",
		"SMTP_PASSWORD":           "smtp-secret",
		"SMTP_FROM":               "noreply@example.test",
		"OWNER_EMAIL":             "owner@example.test",
	} {
		t.Setenv(key, value)
	}
}

func setLiveJanitorEnv(t *testing.T) {
	t.Helper()
	setRequiredJanitorEnv(t)
	t.Setenv("SERVER_NAME", "production.example.invalid")
	t.Setenv("BILLING_ENVIRONMENT", "live")
	t.Setenv("JANITOR_DB_URL", "postgres://janitor:secret@db/database")
	t.Setenv("SMTP_HOST", "smtp.example.test")
	t.Setenv("SMTP_USERNAME", "janitor@example.test")
	t.Setenv("SMTP_PASSWORD", "smtp-secret")
	t.Setenv("SMTP_FROM", "noreply@example.test")
	t.Setenv("OWNER_EMAIL", "owner@example.test")
}

func TestLoadPlanDerivesPublicURLsFromServerName(t *testing.T) {
	setRequiredPlanEnv(t)
	cfg, err := LoadPlan()
	if err != nil {
		t.Fatalf("LoadPlan: %v", err)
	}
	if got, want := cfg.BackendPublicURL, "https://backend.example.invalid"; got != want {
		t.Fatalf("BackendPublicURL = %q, want %q", got, want)
	}
	if got, want := cfg.PlanPublicURL, "https://backend.example.invalid/plan"; got != want {
		t.Fatalf("PlanPublicURL = %q, want %q", got, want)
	}
	if got, want := cfg.MASInternalURL, "http://127.0.0.1:8082"; got != want {
		t.Fatalf("MASInternalURL = %q, want %q", got, want)
	}
	if got, want := cfg.CashierInternalURL, "http://127.0.0.1:9011"; got != want {
		t.Fatalf("CashierInternalURL = %q, want %q", got, want)
	}
}

func TestLoadPlanRequiresValidHostnameAndBillingEnvironment(t *testing.T) {
	for _, tc := range []struct {
		server, billing string
		valid           bool
	}{
		{"example.invalid", "test", true}, {"preview.example.invalid", "live", true},
		{"bad host", "test", false}, {"example.invalid", "production", false},
	} {
		t.Run(tc.server+"/"+tc.billing, func(t *testing.T) {
			setRequiredPlanEnv(t)
			t.Setenv("SERVER_NAME", tc.server)
			t.Setenv("BILLING_ENVIRONMENT", tc.billing)
			_, err := LoadPlan()
			if (err == nil) != tc.valid {
				t.Fatalf("LoadPlan validity = %v, want %v (err=%v)", err == nil, tc.valid, err)
			}
		})
	}
	setRequiredPlanEnv(t)
	t.Setenv("BILLING_ENV", "test")
	if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), "BILLING_ENV") {
		t.Fatal("LoadPlan accepted legacy BILLING_ENV override")
	}
	if err := os.Unsetenv("BILLING_ENV"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"DODO_API_URL", "DODO_MODE", "DODO_API_KEY", "DODO_WEBHOOK_SECRET"} {
		t.Run(name, func(t *testing.T) {
			setRequiredPlanEnv(t)
			t.Setenv(name, "ambient-value")
			if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("LoadPlan accepted ambient Dodo setting %s", name)
			}
		})
	}
}

func TestLoadPlanRequiresServerName(t *testing.T) {
	setRequiredPlanEnv(t)
	t.Setenv("SERVER_NAME", "")
	if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), "SERVER_NAME") {
		t.Fatalf("LoadPlan error = %v, want missing SERVER_NAME", err)
	}
}

func TestLoadPlanRequiresCanonicalMASClientULID(t *testing.T) {
	for _, value := range []string{"plan", "81J00000000000000000000000", "01j00000000000000000000000", "01J0000000000000000000000I"} {
		t.Run(value, func(t *testing.T) {
			setRequiredPlanEnv(t)
			t.Setenv("MAS_OIDC_CLIENT_ID", value)
			if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), "MAS_OIDC_CLIENT_ID") {
				t.Fatalf("LoadPlan error = %v, want canonical MAS client ULID rejection", err)
			}
		})
	}
}

func TestLoadPlanRejectsShortPlanSessionKey(t *testing.T) {
	setRequiredPlanEnv(t)
	t.Setenv("PLAN_SESSION_KEY", "too-short")
	if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), "PLAN_SESSION_KEY") {
		t.Fatal("LoadPlan accepted a short session signing key")
	}
}

func TestLoadPlanRejectsSurroundingWhitespaceInSecrets(t *testing.T) {
	for _, name := range []string{"MAS_OIDC_CLIENT_ID", "MAS_OIDC_CLIENT_SECRET", "PLAN_SESSION_KEY", "PLAN_ASSERTION_PRIVATE_KEY"} {
		t.Run(name, func(t *testing.T) {
			setRequiredPlanEnv(t)
			value := " secret "
			if name == "PLAN_SESSION_KEY" {
				value = " " + strings.Repeat("s", 32)
			}
			if name == "PLAN_ASSERTION_PRIVATE_KEY" {
				value = " " + testPlanPrivateKey()
			}
			t.Setenv(name, value)
			if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("LoadPlan error = %v, want %s whitespace rejection", err, name)
			}
		})
	}
}

func TestLoadPlanRejectsLegacySessionKeyName(t *testing.T) {
	setRequiredPlanEnv(t)
	t.Setenv("SESSION_KEY", strings.Repeat("s", 32))
	if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), "SESSION_KEY") {
		t.Fatalf("LoadPlan error = %v, want legacy SESSION_KEY rejection", err)
	}
}

func TestLoadPlanRejectsInvalidPrivateKeyMaterial(t *testing.T) {
	for _, value := range []string{
		strings.Repeat("A", 86),
		base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize)),
		base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize)) + "=",
	} {
		t.Run(value, func(t *testing.T) {
			setRequiredPlanEnv(t)
			t.Setenv("PLAN_ASSERTION_PRIVATE_KEY", value)
			if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), "PLAN_ASSERTION_PRIVATE_KEY") {
				t.Fatalf("LoadPlan error = %v, want invalid PLAN_ASSERTION_PRIVATE_KEY rejection", err)
			}
		})
	}
}

func TestServerIdentityDerivesPublicHostnames(t *testing.T) {
	for _, tt := range []struct {
		name, serverName, wantOrigin string
	}{
		{"single label", "example.invalid", "https://backend.example.invalid"},
		{"nested hostname", "preview.example.invalid", "https://backend.preview.example.invalid"},
		{"uppercase label", "Preview.Example.Invalid", "https://backend.Preview.Example.Invalid"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			endpoints, err := deriveBackendEndpoints(tt.serverName)
			if err != nil || endpoints.origin != tt.wantOrigin {
				t.Fatalf("deriveBackendEndpoints(%q) = %#v, %v; want %q", tt.serverName, endpoints, err, tt.wantOrigin)
			}
		})
	}
}

func TestServerIdentityRejectsInvalidHostnames(t *testing.T) {
	for _, serverName := range []string{"", "bad host", "-example.invalid", "example_.invalid", "example.invalid."} {
		t.Run(serverName, func(t *testing.T) {
			if _, err := deriveBackendEndpoints(serverName); err == nil {
				t.Fatalf("deriveBackendEndpoints(%q) accepted invalid hostname", serverName)
			}
		})
	}
}

func TestLoadJanitorLoadsPrivateDatabaseURL(t *testing.T) {
	setRequiredJanitorEnv(t)
	cfg, err := LoadJanitor()
	if err != nil {
		t.Fatalf("LoadJanitor: %v", err)
	}
	if got, want := cfg.MASAdminURL, "http://127.0.0.1:8081"; got != want {
		t.Fatalf("MASAdminURL = %q, want %q", got, want)
	}
	if got, want := cfg.JanitorDBURL, "postgres://janitor:secret@db/database"; got != want {
		t.Fatalf("JanitorDBURL = %q, want %q", got, want)
	}
}

func TestLoadJanitorRequiresCompleteSMTP(t *testing.T) {
	for _, name := range []string{"SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM"} {
		t.Run(name, func(t *testing.T) {
			setLiveJanitorEnv(t)
			t.Setenv(name, "")
			_, err := LoadJanitor()
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("LoadJanitor error = %v, want missing %s", err, name)
			}
		})
	}

	setRequiredJanitorEnv(t)
	for _, name := range []string{"SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM"} {
		t.Setenv(name, "")
	}
	t.Setenv("OWNER_EMAIL", "")
	if _, err := LoadJanitor(); err != nil {
		t.Fatalf("LoadJanitor without optional mail configuration: %v", err)
	}

	setLiveJanitorEnv(t)
	t.Setenv("OWNER_EMAIL", "")
	if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), "OWNER_EMAIL") {
		t.Fatalf("LoadJanitor error = %v, want missing OWNER_EMAIL", err)
	}

	setLiveJanitorEnv(t)
	t.Setenv("OWNER_EMAIL", "not-an-email")
	if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), "OWNER_EMAIL") {
		t.Fatalf("LoadJanitor error = %v, want invalid OWNER_EMAIL", err)
	}

	setRequiredJanitorEnv(t)
	t.Setenv("OWNER_EMAIL", "")
	if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), "OWNER_EMAIL") {
		t.Fatalf("LoadJanitor test profile accepted missing OWNER_EMAIL: %v", err)
	}
}

func TestLoadJanitorRequiresCanonicalMASClientULID(t *testing.T) {
	for _, value := range []string{"janitor", "81J00000000000000000000000", "01j00000000000000000000000", "01J0000000000000000000000O"} {
		t.Run(value, func(t *testing.T) {
			setRequiredJanitorEnv(t)
			t.Setenv("MAS_ADMIN_CLIENT_ID", value)
			if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), "MAS_ADMIN_CLIENT_ID") {
				t.Fatalf("LoadJanitor error = %v, want canonical MAS client ULID rejection", err)
			}
		})
	}
}

func TestLoadJanitorRejectsSurroundingWhitespaceInConfiguration(t *testing.T) {
	for _, name := range []string{"MAS_ADMIN_CLIENT_ID", "MAS_ADMIN_CLIENT_SECRET", "SMTP_PASSWORD"} {
		t.Run(name, func(t *testing.T) {
			setRequiredJanitorEnv(t)
			t.Setenv(name, " secret ")
			if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("LoadJanitor error = %v, want %s whitespace rejection", err, name)
			}
		})
	}
}

func TestLoadJanitorParsesAndNormalizesDeliveryMailboxes(t *testing.T) {
	setLiveJanitorEnv(t)
	t.Setenv("OWNER_EMAIL", "Owner <owner@example.test>")
	t.Setenv("SMTP_FROM", "TeleCrypt <noreply@example.test>")
	cfg, err := LoadJanitor()
	if err != nil {
		t.Fatalf("LoadJanitor: %v", err)
	}
	if cfg.OwnerEmail != "owner@example.test" || cfg.SMTPFrom != "noreply@example.test" {
		t.Fatalf("mailboxes = (%q, %q), want bare parsed addresses", cfg.OwnerEmail, cfg.SMTPFrom)
	}
}

func TestLoadJanitorRejectsInvalidSMTPFrom(t *testing.T) {
	setLiveJanitorEnv(t)
	t.Setenv("SMTP_FROM", "not-an-email")
	if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), "SMTP_FROM") {
		t.Fatalf("LoadJanitor error = %v, want invalid SMTP_FROM rejection", err)
	}
}

func TestLoadJanitorRejectsInvalidProfileValues(t *testing.T) {
	setRequiredJanitorEnv(t)
	t.Setenv("SERVER_NAME", "bad host")
	if _, err := LoadJanitor(); err == nil {
		t.Fatal("LoadJanitor accepted an invalid hostname")
	}
	setRequiredJanitorEnv(t)
	t.Setenv("BILLING_ENVIRONMENT", "production")
	if _, err := LoadJanitor(); err == nil {
		t.Fatal("LoadJanitor accepted an invalid billing environment")
	}
}

func TestLoadJanitorUsesProductionDatabaseIdentity(t *testing.T) {
	setLiveJanitorEnv(t)
	t.Setenv("SERVER_NAME", "production.example.invalid")
	t.Setenv("BILLING_ENVIRONMENT", "live")
	t.Setenv("JANITOR_DB_URL", "postgres://janitor:secret@db/database")
	if _, err := LoadJanitor(); err != nil {
		t.Fatalf("LoadJanitor in production: %v", err)
	}
}

func TestLoadAndValidateRegistrationDerivesPublicURLs(t *testing.T) {
	t.Setenv("SERVER_NAME", "production.example.invalid")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := cfg.BackendPublicURL, "https://backend.production.example.invalid"; got != want {
		t.Fatalf("BackendPublicURL = %q, want %q", got, want)
	}
	if got, want := cfg.MASPublicURL, "https://backend.production.example.invalid"; got != want {
		t.Fatalf("MASPublicURL = %q, want %q", got, want)
	}
	if got, want := cfg.PlanPublicURL, "https://backend.production.example.invalid/plan"; got != want {
		t.Fatalf("PlanPublicURL = %q, want %q", got, want)
	}
	if err := cfg.ValidateRegistration(); err != nil {
		t.Fatalf("ValidateRegistration rejected a valid configuration: %v", err)
	}
	cfg.MASPublicURL = "http://127.0.0.1:8082"
	if err := cfg.ValidateRegistration(); err == nil {
		t.Fatal("ValidateRegistration accepted an internal MAS endpoint")
	}
}

func TestRegistrationLoadRejectsInvalidHostname(t *testing.T) {
	t.Setenv("SERVER_NAME", "bad host")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SERVER_NAME") {
		t.Fatalf("Load accepted an invalid hostname: %v", err)
	}
}

func TestLoadPlanRequiresMASAccountCredential(t *testing.T) {
	for _, name := range []string{"MAS_ADMIN_CLIENT_ID", "MAS_ADMIN_CLIENT_SECRET"} {
		t.Run(name, func(t *testing.T) {
			setRequiredPlanEnv(t)
			t.Setenv(name, "")
			if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("LoadPlan = %v, want missing %s", err, name)
			}
		})
	}
	setRequiredPlanEnv(t)
	cfg, err := LoadPlan()
	if err != nil || cfg.MASAdminURL != "http://127.0.0.1:8081" || cfg.MASAdminClientID != testPlanClientID || cfg.MASAdminClientSecret != "admin-test-secret" {
		t.Fatalf("Plan MAS admin configuration = %#v, %v", cfg, err)
	}
}
