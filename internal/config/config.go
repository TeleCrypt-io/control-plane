// Package config loads each public control-plane binary configuration.
package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"strings"

	"github.com/TeleCrypt-io/controlplane/internal/db"
)

// Config contains the public endpoints shared by the control-plane services.
type Config struct {
	BackendPublicURL string
	MASPublicURL     string
	PlanPublicURL    string
	ServerName       string
}

func Load() (*Config, error) {
	serverName, endpoints, err := loadServerIdentity()
	if err != nil {
		return nil, err
	}
	return &Config{
		BackendPublicURL: endpoints.origin,
		MASPublicURL:     endpoints.mas,
		PlanPublicURL:    endpoints.plan,
		ServerName:       serverName,
	}, nil
}

// ValidateRegistration rejects a configuration that would weaken Registration's public OAuth boundary or
// make the in-process backstop unavailable. Registration has no internal MAS credential, so its MAS,
// homeserver, and Plan URLs must all be browser-visible HTTPS endpoints.
func (c *Config) ValidateRegistration() error {
	endpoints, err := deriveBackendEndpoints(c.ServerName)
	if err != nil {
		return err
	}
	if c.BackendPublicURL != endpoints.origin || c.MASPublicURL != endpoints.mas || c.PlanPublicURL != endpoints.plan {
		return fmt.Errorf("public endpoints must be derived from SERVER_NAME")
	}
	for _, endpoint := range []struct {
		name string
		url  string
	}{
		{"derived backend URL", c.BackendPublicURL},
		{"derived MAS URL", c.MASPublicURL},
		{"derived Plan overview URL", c.PlanPublicURL},
	} {
		if err := validatePublicHTTPSURL(endpoint.url, endpoint.name); err != nil {
			return err
		}
	}
	return nil
}

// JanitorConfig is Janitor configuration. Cashier alone writes payment state; Janitor verifies
// its deployment identity before it reads the two Cashier-owned Janitor views.
type JanitorConfig struct {
	BillingEnvironment   string
	MASAdminURL          string
	MASAdminClientID     string
	MASAdminClientSecret string
	SynapseAdminURL      string
	SynapseAdminToken    string
	JanitorDBURL         string
	DodoReadOnlyAPIURL   string
	DodoReadOnlyAPIKey   string
	ServerName           string
	OwnerEmail           string
	SMTPHost             string
	SMTPUsername         string
	SMTPPassword         string
	SMTPFrom             string
}

func LoadJanitor() (*JanitorConfig, error) {
	serverName, billingEnvironment, _, err := loadBillingIdentity()
	if err != nil {
		return nil, err
	}
	c := &JanitorConfig{
		BillingEnvironment:   billingEnvironment,
		MASAdminURL:          masAdminURL,
		MASAdminClientID:     os.Getenv("MAS_ADMIN_CLIENT_ID"),
		MASAdminClientSecret: os.Getenv("MAS_ADMIN_CLIENT_SECRET"),
		SynapseAdminURL:      synapseAdminURL,
		SynapseAdminToken:    os.Getenv("SYNAPSE_ADMIN_TOKEN"),
		JanitorDBURL:         os.Getenv("JANITOR_DB_URL"),
		DodoReadOnlyAPIURL:   os.Getenv("DODO_READ_ONLY_API_URL"),
		DodoReadOnlyAPIKey:   os.Getenv("DODO_READ_ONLY_API_KEY"),
		ServerName:           serverName,
		OwnerEmail:           os.Getenv("OWNER_EMAIL"),
		SMTPHost:             os.Getenv("SMTP_HOST"),
		SMTPUsername:         os.Getenv("SMTP_USERNAME"),
		SMTPPassword:         os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:             os.Getenv("SMTP_FROM"),
	}
	required := []envValue{
		{"MAS_ADMIN_CLIENT_ID", c.MASAdminClientID},
		{"MAS_ADMIN_CLIENT_SECRET", c.MASAdminClientSecret}, {"SYNAPSE_ADMIN_TOKEN", c.SynapseAdminToken},
		{"JANITOR_DB_URL", c.JanitorDBURL},
		{"SERVER_NAME", c.ServerName},
	}
	if err := requireEnvValues(required, "missing required env vars"); err != nil {
		return nil, err
	}
	if !validMASClientID(c.MASAdminClientID) {
		return nil, fmt.Errorf("MAS_ADMIN_CLIENT_ID must be a canonical 26-character MAS ULID")
	}
	optional := []envValue{
		{"OWNER_EMAIL", c.OwnerEmail}, {"SMTP_HOST", c.SMTPHost},
		{"SMTP_USERNAME", c.SMTPUsername}, {"SMTP_PASSWORD", c.SMTPPassword},
		{"SMTP_FROM", c.SMTPFrom},
	}
	if err := rejectSurroundingWhitespace(optional); err != nil {
		return nil, err
	}
	if c.DodoReadOnlyAPIURL != "" || c.DodoReadOnlyAPIKey != "" {
		if err := requireEnvValues([]envValue{{"DODO_READ_ONLY_API_URL", c.DodoReadOnlyAPIURL}, {"DODO_READ_ONLY_API_KEY", c.DodoReadOnlyAPIKey}}, "missing required Janitor Dodo read-only env vars"); err != nil {
			return nil, err
		}
		if c.OwnerEmail == "" {
			return nil, fmt.Errorf("OWNER_EMAIL is required when Janitor Dodo read-only reconciliation is enabled")
		}
		if err := validatePublicHTTPSURL(c.DodoReadOnlyAPIURL, "DODO_READ_ONLY_API_URL"); err != nil {
			return nil, err
		}
	}
	mailConfigured := false
	for _, value := range optional {
		if value.value != "" {
			mailConfigured = true
			break
		}
	}
	if mailConfigured {
		if err := requireEnvValues([]envValue{
			{"OWNER_EMAIL", c.OwnerEmail}, {"SMTP_HOST", c.SMTPHost},
			{"SMTP_USERNAME", c.SMTPUsername}, {"SMTP_PASSWORD", c.SMTPPassword},
			{"SMTP_FROM", c.SMTPFrom},
		}, "missing required Janitor mail env vars"); err != nil {
			return nil, err
		}
		if c.OwnerEmail, err = parseMailbox("OWNER_EMAIL", c.OwnerEmail); err != nil {
			return nil, err
		}
		if c.SMTPFrom, err = parseMailbox("SMTP_FROM", c.SMTPFrom); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// PlanConfig contains the browser-facing service configuration. Plan has no MAS-admin,
// Synapse-admin, or database credentials.
type PlanConfig struct {
	BillingEnvironment      string
	ServerName              string
	BackendPublicURL        string
	MASInternalURL          string
	PlanPublicURL           string
	CashierInternalURL      string // fixed pod-local endpoint
	MASClientID             string
	MASClientSecret         string
	PlanSessionKey          string
	PlanAssertionPrivateKey string
}

func LoadPlan() (*PlanConfig, error) {
	serverName, billingEnvironment, endpoints, err := loadBillingIdentity()
	if err != nil {
		return nil, err
	}
	c := &PlanConfig{
		BillingEnvironment:      billingEnvironment,
		ServerName:              serverName,
		BackendPublicURL:        endpoints.origin,
		MASInternalURL:          masInternalURL,
		CashierInternalURL:      cashierInternalURL,
		MASClientID:             os.Getenv("MAS_OIDC_CLIENT_ID"),
		MASClientSecret:         os.Getenv("MAS_OIDC_CLIENT_SECRET"),
		PlanSessionKey:          os.Getenv("PLAN_SESSION_KEY"),
		PlanAssertionPrivateKey: os.Getenv("PLAN_ASSERTION_PRIVATE_KEY"),
	}
	if _, present := os.LookupEnv("SESSION_KEY"); present {
		return nil, fmt.Errorf("SESSION_KEY must be unset; use PLAN_SESSION_KEY")
	}
	for _, key := range []string{"MAS_ADMIN_CLIENT_ID", "MAS_ADMIN_CLIENT_SECRET"} {
		if _, present := os.LookupEnv(key); present {
			return nil, fmt.Errorf("%s must be unset for Plan", key)
		}
	}
	required := []envValue{
		{"MAS_OIDC_CLIENT_ID", c.MASClientID}, {"MAS_OIDC_CLIENT_SECRET", c.MASClientSecret},
		{"PLAN_SESSION_KEY", c.PlanSessionKey}, {"PLAN_ASSERTION_PRIVATE_KEY", c.PlanAssertionPrivateKey},
	}
	if err := requireEnvValues(required, "missing required env var"); err != nil {
		return nil, err
	}
	if !validMASClientID(c.MASClientID) {
		return nil, fmt.Errorf("MAS_OIDC_CLIENT_ID must be a canonical 26-character MAS ULID")
	}
	if len(c.PlanSessionKey) < 32 {
		return nil, fmt.Errorf("PLAN_SESSION_KEY must contain at least 32 bytes")
	}
	if err := validatePlanAssertionPrivateKey(c.PlanAssertionPrivateKey); err != nil {
		return nil, err
	}
	c.PlanPublicURL = endpoints.plan
	if err := validatePublicHTTPSURL(c.BackendPublicURL, "derived backend URL"); err != nil {
		return nil, err
	}
	return c, nil
}

const (
	masAdminURL        = "http://127.0.0.1:8081"
	masInternalURL     = "http://127.0.0.1:8082"
	synapseAdminURL    = "http://127.0.0.1:8008"
	cashierInternalURL = "http://127.0.0.1:9011"
)

type backendEndpoints struct {
	origin string
	mas    string
	plan   string
}

type envValue struct {
	name  string
	value string
}

func validMASClientID(value string) bool {
	if len(value) != 26 || value[0] > '7' {
		return false
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i := range value {
		if !strings.ContainsRune(alphabet, rune(value[i])) {
			return false
		}
	}
	return true
}

func requireEnvValues(values []envValue, missingPrefix string) error {
	var missing []string
	for _, value := range values {
		if value.value == "" {
			missing = append(missing, value.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s: %s", missingPrefix, strings.Join(missing, ", "))
	}
	return rejectSurroundingWhitespace(values)
}

func rejectSurroundingWhitespace(values []envValue) error {
	for _, value := range values {
		if value.value != "" {
			if err := requireNonEmptyNoSurroundingWhitespace(value.name, value.value); err != nil {
				return err
			}
		}
	}
	return nil
}

func loadServerName() (string, error) {
	serverName := os.Getenv("SERVER_NAME")
	if serverName == "" {
		return "", fmt.Errorf("missing required env var: SERVER_NAME")
	}
	if err := requireNonEmptyNoSurroundingWhitespace("SERVER_NAME", serverName); err != nil {
		return "", err
	}
	return serverName, nil
}

func loadServerIdentity() (string, backendEndpoints, error) {
	serverName, err := loadServerName()
	if err != nil {
		return "", backendEndpoints{}, err
	}
	endpoints, err := deriveBackendEndpoints(serverName)
	if err != nil {
		return "", backendEndpoints{}, err
	}
	return serverName, endpoints, nil
}

// loadBillingIdentity is used only by Plan and Janitor. Registration is topology-only and may
// derive a public endpoint before a billing profile exists, but these two services hold
// billing-sensitive behavior and therefore require an explicit server name and billing mode. The
// nonsecret billing value is never inferred from credentials or hostname.
func loadBillingIdentity() (string, string, backendEndpoints, error) {
	serverName, endpoints, err := loadServerIdentity()
	if err != nil {
		return "", "", backendEndpoints{}, err
	}
	billingEnvironment, present := os.LookupEnv("BILLING_ENVIRONMENT")
	if !present || billingEnvironment == "" {
		return "", "", backendEndpoints{}, fmt.Errorf("missing required env var: BILLING_ENVIRONMENT")
	}
	if err := requireNonEmptyNoSurroundingWhitespace("BILLING_ENVIRONMENT", billingEnvironment); err != nil {
		return "", "", backendEndpoints{}, err
	}
	if err := db.ValidateDeploymentProfile(serverName, billingEnvironment); err != nil {
		return "", "", backendEndpoints{}, err
	}
	if _, present := os.LookupEnv("BILLING_ENV"); present {
		return "", "", backendEndpoints{}, fmt.Errorf("BILLING_ENV must be unset")
	}
	for _, key := range []string{
		"DODO_ENVIRONMENT", "DODO_MODE", "DODO_BASE_URL", "DODO_API_URL", "DODO_API_BASE_URL",
		"DODO_CHECKOUT_URL", "DODO_PORTAL_URL", "DODO_API_KEY", "DODO_API_TOKEN",
		"DODO_WEBHOOK_SECRET", "DODO_SIGNING_SECRET", "DODO_PRODUCT_ID",
	} {
		if _, present := os.LookupEnv(key); present {
			return "", "", backendEndpoints{}, fmt.Errorf("%s must be unset", key)
		}
	}
	return serverName, billingEnvironment, endpoints, nil
}

func deriveBackendEndpoints(serverName string) (backendEndpoints, error) {
	if err := db.ValidateServerName(serverName); err != nil {
		return backendEndpoints{}, err
	}
	backendHost := "backend." + serverName
	origin := "https://" + backendHost
	return backendEndpoints{
		origin: origin,
		mas:    origin,
		plan:   origin + "/plan/overview",
	}, nil
}

func requireNonEmptyNoSurroundingWhitespace(name, value string) error {
	if value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must be non-empty and must not have surrounding whitespace", name)
	}
	return nil
}

func parseMailbox(name, value string) (string, error) {
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address == "" {
		return "", fmt.Errorf("%s must be a valid email address", name)
	}
	return address.Address, nil
}

func validatePlanAssertionPrivateKey(value string) error {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != ed25519.PrivateKeySize ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		return fmt.Errorf("PLAN_ASSERTION_PRIVATE_KEY must be a raw URL-safe base64 Ed25519 private key")
	}
	expected := ed25519.NewKeyFromSeed(decoded[:ed25519.SeedSize])
	if !bytes.Equal(decoded, expected) {
		return fmt.Errorf("PLAN_ASSERTION_PRIVATE_KEY must contain a seed-matching Ed25519 private key")
	}
	return nil
}

func validatePublicHTTPSURL(raw, name string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must be a public HTTPS URL", name)
	}
	return nil
}
