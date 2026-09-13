package db

import (
	"fmt"

	"github.com/TeleCrypt-io/controlplane/postgresurl"
)

func ValidateJanitorDatabaseURL(raw string) error {
	if err := postgresurl.Validate(raw); err != nil {
		return fmt.Errorf("JANITOR_DB_URL %w", err)
	}
	return nil
}
