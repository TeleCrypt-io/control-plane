// Package postgresurl validates the explicit connection inputs shared by TeleCrypt services.
// Service-specific database identities, roles, schemas, and environment policy stay with callers.
package postgresurl

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// Validate checks one explicit PostgreSQL target and its supported connection options before
// pgx parses it. File/service and target-changing query options are not accepted. Standard URL
// escaping, DNS spelling, and numeric port spelling are left to the standard parsers.
func Validate(raw string) error {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return fmt.Errorf("must be a non-empty Postgres URL without surrounding whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Opaque != "" || u.Fragment != "" || u.User == nil || u.Hostname() == "" || strings.Contains(u.Host, ",") {
		return fmt.Errorf("must identify one explicit Postgres target")
	}
	if port := u.Port(); port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			return fmt.Errorf("must identify a valid Postgres port")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return fmt.Errorf("must identify a valid Postgres port")
	}
	database := strings.TrimPrefix(u.Path, "/")
	if database == "" || strings.Contains(database, "/") || whitespaceOrControl(database) || u.User.Username() == "" || whitespaceOrControl(u.User.Username()) {
		return fmt.Errorf("must identify a database and user")
	}
	password, present := u.User.Password()
	if !present || password == "" || whitespaceOrControl(password) {
		return fmt.Errorf("must include an explicit non-whitespace database password")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fmt.Errorf("contains an invalid query")
	}
	for key, values := range query {
		switch key {
		case "sslmode", "connect_timeout", "application_name":
		default:
			return fmt.Errorf("query parameter %q is not allowed", key)
		}
		if len(values) != 1 || values[0] == "" || whitespaceOrControl(values[0]) {
			return fmt.Errorf("query parameter %q must have one non-whitespace value", key)
		}
	}
	return nil
}

func whitespaceOrControl(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0
}
