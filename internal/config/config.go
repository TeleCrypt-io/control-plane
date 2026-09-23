// Package config loads each public control-plane binary configuration.
package config

import (
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"strings"
)

// Config contains the public endpoints shared by the control-plane services.
type Config struct {
	BackendPublicURL string
	MASPublicURL     string
	PlanPublicURL    string
	ServerName       string
}

func Load() (*Config, error) {
	if err := rejectServiceTokens("Registration", "CASHIER_PLAN_TOKEN", "CASHIER_JANITOR_TOKEN", "CASHIER_SYNAPSE_TOKEN"); err != nil {
		return nil, err
	}
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

// JanitorConfig contains only the external-service credentials Janitor uses. Cashier owns all
// billing and lifecycle database state.
type JanitorConfig struct {
	MASAdminURL          string
	MASAdminClientID     string
	MASAdminClientSecret string
	SynapseAdminURL      string
	SynapseAdminToken    string
	CashierToken         string
	DodoReadOnlyAPIURL   string
	DodoReadOnlyAPIKey   string
	ServerName           string
	OperatorEmail        string
	SMTPHost             string
	SMTPUsername         string
	SMTPPassword         string
	SMTPFrom             string
}

func LoadJanitor() (*JanitorConfig, error) {
	if err := rejectServiceTokens("Janitor", "CASHIER_PLAN_TOKEN", "CASHIER_SYNAPSE_TOKEN"); err != nil {
		return nil, err
	}
	serverName, _, _, err := loadBillingIdentity()
	if err != nil {
		return nil, err
	}
	cashierToken, err := loadCashierServiceToken("CASHIER_JANITOR_TOKEN")
	if err != nil {
		return nil, err
	}
	c := &JanitorConfig{
		MASAdminURL:          masAdminURL,
		MASAdminClientID:     os.Getenv("MAS_ADMIN_CLIENT_ID"),
		MASAdminClientSecret: os.Getenv("MAS_ADMIN_CLIENT_SECRET"),
		SynapseAdminURL:      synapseAdminURL,
		SynapseAdminToken:    os.Getenv("SYNAPSE_ADMIN_TOKEN"),
		CashierToken:         cashierToken,
		DodoReadOnlyAPIURL:   os.Getenv("DODO_READ_ONLY_API_URL"),
		DodoReadOnlyAPIKey:   os.Getenv("DODO_READ_ONLY_API_KEY"),
		ServerName:           serverName,
		OperatorEmail:        os.Getenv("OPERATOR_EMAIL"),
		SMTPHost:             os.Getenv("SMTP_HOST"),
		SMTPUsername:         os.Getenv("SMTP_USERNAME"),
		SMTPPassword:         os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:             os.Getenv("SMTP_FROM"),
	}
	required := []envValue{
		{"MAS_ADMIN_CLIENT_ID", c.MASAdminClientID},
		{"MAS_ADMIN_CLIENT_SECRET", c.MASAdminClientSecret}, {"SYNAPSE_ADMIN_TOKEN", c.SynapseAdminToken},
		{"SERVER_NAME", c.ServerName},
	}
	if err := requireEnvValues(required, "missing required env vars"); err != nil {
		return nil, err
	}
	if !validMASClientID(c.MASAdminClientID) {
		return nil, fmt.Errorf("MAS_ADMIN_CLIENT_ID must be a canonical 26-character MAS ULID")
	}
	optional := []envValue{
		{"OPERATOR_EMAIL", c.OperatorEmail}, {"SMTP_HOST", c.SMTPHost},
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
			{"OPERATOR_EMAIL", c.OperatorEmail}, {"SMTP_HOST", c.SMTPHost},
			{"SMTP_USERNAME", c.SMTPUsername}, {"SMTP_PASSWORD", c.SMTPPassword},
			{"SMTP_FROM", c.SMTPFrom},
		}, "missing required Janitor mail env vars"); err != nil {
			return nil, err
		}
		if c.OperatorEmail, err = parseMailbox("OPERATOR_EMAIL", c.OperatorEmail); err != nil {
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
	BillingEnvironment string
	ServerName         string
	BackendPublicURL   string
	MASInternalURL     string
	PlanPublicURL      string
	CashierInternalURL string // fixed pod-local endpoint
	CashierToken       string
	MASClientID        string
	MASClientSecret    string
	PlanSessionKey     string
	BillingLink1       string
	BillingLink2       string
	BillingLink3       string
	BillingLink4       string
	BillingPortalURL   string
}

func LoadPlan() (*PlanConfig, error) {
	if err := rejectServiceTokens("Plan", "CASHIER_JANITOR_TOKEN", "CASHIER_SYNAPSE_TOKEN"); err != nil {
		return nil, err
	}
	serverName, billingEnvironment, endpoints, err := loadBillingIdentity()
	if err != nil {
		return nil, err
	}
	cashierToken, err := loadCashierServiceToken("CASHIER_PLAN_TOKEN")
	if err != nil {
		return nil, err
	}
	c := &PlanConfig{
		BillingEnvironment: billingEnvironment,
		ServerName:         serverName,
		BackendPublicURL:   endpoints.origin,
		MASInternalURL:     masInternalURL,
		CashierInternalURL: cashierInternalURL,
		CashierToken:       cashierToken,
		MASClientID:        os.Getenv("MAS_OIDC_CLIENT_ID"),
		MASClientSecret:    os.Getenv("MAS_OIDC_CLIENT_SECRET"),
		PlanSessionKey:     os.Getenv("PLAN_SESSION_KEY"),
		BillingLink1:       os.Getenv("PLAN_BILLING_LINK_1"),
		BillingLink2:       os.Getenv("PLAN_BILLING_LINK_2"),
		BillingLink3:       os.Getenv("PLAN_BILLING_LINK_3"),
		BillingLink4:       os.Getenv("PLAN_BILLING_LINK_4"),
		BillingPortalURL:   os.Getenv("PLAN_BILLING_PORTAL_URL"),
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
		{"PLAN_SESSION_KEY", c.PlanSessionKey},
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
	for _, link := range []envValue{
		{"PLAN_BILLING_LINK_1", c.BillingLink1},
		{"PLAN_BILLING_LINK_2", c.BillingLink2},
		{"PLAN_BILLING_LINK_3", c.BillingLink3},
		{"PLAN_BILLING_LINK_4", c.BillingLink4},
		{"PLAN_BILLING_PORTAL_URL", c.BillingPortalURL},
	} {
		if err := requireEnvValues([]envValue{link}, "missing required Plan billing link env var"); err != nil {
			return nil, err
		}
		if err := validatePublicHTTPSLink(link.value, link.name); err != nil {
			return nil, err
		}
	}
	c.PlanPublicURL = endpoints.plan
	if err := validatePublicHTTPSURL(c.BackendPublicURL, "derived backend URL"); err != nil {
		return nil, err
	}
	return c, nil
}

func loadCashierServiceToken(name string) (string, error) {
	value := os.Getenv(name)
	if len(value) != 64 {
		return "", fmt.Errorf("%s must be 64 lowercase hexadecimal characters", name)
	}
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return "", fmt.Errorf("%s must be 64 lowercase hexadecimal characters", name)
		}
	}
	return value, nil
}

func rejectServiceTokens(service string, names ...string) error {
	for _, name := range names {
		if _, present := os.LookupEnv(name); present {
			return fmt.Errorf("%s must be unset for %s", name, service)
		}
	}
	return nil
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
	if billingEnvironment != "test" && billingEnvironment != "live" {
		return "", "", backendEndpoints{}, fmt.Errorf("invalid SERVER_NAME/BILLING_ENVIRONMENT profile")
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
	if err := validateServerName(serverName); err != nil {
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

func validateServerName(serverName string) error {
	if len(serverName) == 0 || len(serverName) > 253 || strings.TrimSpace(serverName) != serverName {
		return fmt.Errorf("SERVER_NAME must be a valid hostname")
	}
	for _, label := range strings.Split(serverName, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("SERVER_NAME must be a valid hostname")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return fmt.Errorf("SERVER_NAME must be a valid hostname")
			}
		}
	}
	return nil
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

func validatePublicHTTPSURL(raw, name string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must be a public HTTPS URL", name)
	}
	return nil
}

func validatePublicHTTPSLink(raw, name string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%s must be a public HTTPS link", name)
	}
	return nil
}
