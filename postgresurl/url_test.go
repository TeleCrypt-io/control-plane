package postgresurl

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEquivalentURLSpellingsKeepTheSameConnectionIdentity(t *testing.T) {
	for _, raw := range []string{
		"postgres://service_user:secret@DB:05432/service_database?%73slmode=disable&connect_timeout=5",
		"postgresql://service%5Fuser:secret@DB:5432/service%5Fdatabase?sslmode=disable&connect_timeout=5&",
	} {
		if err := Validate(raw); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		config, err := pgxpool.ParseConfig(raw)
		if err != nil {
			t.Fatalf("pgx parse: %v", err)
		}
		c := config.ConnConfig
		if c.User != "service_user" || c.Database != "service_database" || c.Host != "DB" || c.Port != 5432 || c.Password != "secret" {
			t.Fatal("equivalent URL changed the effective connection identity")
		}
	}
}

func TestRejectsMissingTargetCredentialsAndUnsupportedOptions(t *testing.T) {
	for _, raw := range []string{
		"", "postgres:service", "postgres://db/database", "postgres://user@db/database",
		"postgres://user:@db/database", "postgres://user:secret@db/", "postgres://user:secret@/database",
		"postgres://user:secret@db,other/database", "postgres://user:secret@db:0/database",
		"postgres://user:secret@db:65536/database", "postgres://user:secret@db/database/extra",
		"postgres://user:secret@db/database#fragment",
		"postgres://user:secret@db/database?servicefile=/tmp/service.conf",
		"postgres://user:secret@db/database?%73ervice=redirected",
		"postgres://user:secret@db/database?passfile=/tmp/password",
		"postgres://user:secret@db/database?sslkey=/tmp/key",
		"postgres://user:secret@db/database?sslcert=/tmp/cert",
		"postgres://user:secret@db/database?sslrootcert=/tmp/ca",
		"postgres://user:secret@db/database?host=other",
		"postgres://user:secret@db/database?user=other",
		"postgres://user:secret@db/database?database=other",
		"postgres://user:secret@db/database?port=6543",
		"postgres://user:secret@db/database?options=-c%20search_path=public",
		"postgres://user:secret@db/database?search_path=public",
		"postgres://user:secret@db/database?sslmode=require&%73slmode=disable",
		"postgres://user:secret@db/database?sslmode=",
		"postgres://user:secret@db/database?application_name=bad%0Avalue",
		"postgres://user:secret@db/database?sslmode=%ZZ",
	} {
		if err := Validate(raw); err == nil {
			t.Errorf("accepted invalid connection URL %q", raw)
		}
	}
}
