package db

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestJanitorDatabaseContractPG17(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres role/view test")
	}
	ctx := context.Background()
	adminPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	const (
		janitorRole = "controlplane_test_janitor"
		cashierRole = "controlplane_test_cashier"
		password    = "controlplane_test_password"
	)
	setup := fmt.Sprintf(`
		DROP SCHEMA IF EXISTS cashier CASCADE;
		DROP SCHEMA IF EXISTS janitor CASCADE;
		DROP ROLE IF EXISTS %s;
		DROP ROLE IF EXISTS %s;
		CREATE ROLE %s LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '%s';
		CREATE ROLE %s LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '%s';
		CREATE SCHEMA janitor AUTHORIZATION %s;
		REVOKE ALL ON SCHEMA janitor FROM PUBLIC;
		CREATE SCHEMA cashier AUTHORIZATION %s;
		REVOKE ALL ON SCHEMA cashier FROM PUBLIC;
		GRANT USAGE ON SCHEMA cashier TO %s;
		CREATE TABLE cashier.identity_source (singleton BOOLEAN PRIMARY KEY, server_name TEXT NOT NULL, billing_environment TEXT NOT NULL);
		INSERT INTO cashier.identity_source VALUES (TRUE, 'stage.telecrypt.io', 'test');
		CREATE VIEW cashier.janitor_deployment_identity WITH (security_barrier = true) AS SELECT server_name, billing_environment FROM cashier.identity_source;
		CREATE VIEW cashier.janitor_lifecycle_actions WITH (security_barrier = true) AS
			SELECT CAST(NULL AS TEXT) AS mxid, CAST(NULL AS BIGINT) AS revision,
			       CAST(NULL AS TEXT) AS action, CAST(NULL AS TIMESTAMPTZ) AS due_at,
			       CAST(NULL AS TEXT) AS desired_user_type WHERE FALSE;
		CREATE FUNCTION cashier.janitor_sync_account(TEXT, TIMESTAMPTZ) RETURNS VOID LANGUAGE plpgsql AS $$ BEGIN RETURN; END $$;
		CREATE FUNCTION cashier.janitor_claim_suspension(TEXT, BIGINT) RETURNS TABLE(due_at TIMESTAMPTZ, desired_user_type TEXT) LANGUAGE SQL AS $$ SELECT NULL::TIMESTAMPTZ, NULL::TEXT WHERE FALSE $$;
		CREATE FUNCTION cashier.janitor_complete_suspension(TEXT, BIGINT) RETURNS TABLE(revision BIGINT, suspended_at TIMESTAMPTZ) LANGUAGE SQL AS $$ SELECT NULL::BIGINT, NULL::TIMESTAMPTZ WHERE FALSE $$;
		CREATE FUNCTION cashier.janitor_start_removal(TEXT, BIGINT) RETURNS TABLE(revision BIGINT, removal_started_at TIMESTAMPTZ) LANGUAGE SQL AS $$ SELECT NULL::BIGINT, NULL::TIMESTAMPTZ WHERE FALSE $$;
		CREATE FUNCTION cashier.janitor_finish_removal(TEXT, BIGINT) RETURNS TABLE(revision BIGINT, removed_at TIMESTAMPTZ) LANGUAGE SQL AS $$ SELECT NULL::BIGINT, NULL::TIMESTAMPTZ WHERE FALSE $$;
		ALTER TABLE cashier.identity_source OWNER TO %s;
		ALTER VIEW cashier.janitor_deployment_identity OWNER TO %s;
		ALTER VIEW cashier.janitor_lifecycle_actions OWNER TO %s;
		ALTER FUNCTION cashier.janitor_sync_account(TEXT, TIMESTAMPTZ) OWNER TO %s;
		ALTER FUNCTION cashier.janitor_claim_suspension(TEXT, BIGINT) OWNER TO %s;
		ALTER FUNCTION cashier.janitor_complete_suspension(TEXT, BIGINT) OWNER TO %s;
		ALTER FUNCTION cashier.janitor_start_removal(TEXT, BIGINT) OWNER TO %s;
		ALTER FUNCTION cashier.janitor_finish_removal(TEXT, BIGINT) OWNER TO %s;
		GRANT SELECT ON cashier.janitor_deployment_identity, cashier.janitor_lifecycle_actions TO %s;
		GRANT EXECUTE ON FUNCTION cashier.janitor_sync_account(TEXT, TIMESTAMPTZ), cashier.janitor_claim_suspension(TEXT, BIGINT), cashier.janitor_complete_suspension(TEXT, BIGINT), cashier.janitor_start_removal(TEXT, BIGINT), cashier.janitor_finish_removal(TEXT, BIGINT) TO %s;
	`, janitorRole, cashierRole, janitorRole, password, cashierRole, password, janitorRole, cashierRole, janitorRole, cashierRole, cashierRole, cashierRole, cashierRole, cashierRole, cashierRole, cashierRole, cashierRole, janitorRole, janitorRole)
	if _, err := adminPool.Exec(ctx, setup); err != nil {
		t.Fatalf("prepare view fixture: %v", err)
	}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(), fmt.Sprintf(`DROP SCHEMA IF EXISTS cashier CASCADE; DROP SCHEMA IF EXISTS janitor CASCADE; DROP ROLE IF EXISTS %s; DROP ROLE IF EXISTS %s;`, cashierRole, janitorRole))
		adminPool.Close()
	})
	parsedDSN, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse TEST_DATABASE_URL: %v", err)
	}
	parsedDSN.User = url.UserPassword(janitorRole, password)
	janitorDSN := parsedDSN.String()
	janitorPool, err := OpenJanitorPool(ctx, janitorDSN)
	if err != nil {
		t.Fatalf("OpenJanitorPool: %v", err)
	}
	t.Cleanup(janitorPool.Close)
	if err := ValidateJanitorRole(ctx, janitorPool); err != nil {
		t.Fatalf("ValidateJanitorRole: %v", err)
	}
	if err := Migrate(ctx, janitorPool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	var current string
	if err := janitorPool.QueryRow(ctx, `SELECT current_user`).Scan(&current); err != nil {
		t.Fatalf("current_user: %v", err)
	}
	if current != janitorRole {
		t.Fatalf("current_user = %q, want %q", current, janitorRole)
	}
	if err := ValidateJanitorSchemaACL(ctx, janitorPool); err != nil {
		t.Fatalf("ValidateJanitorSchemaACL: %v", err)
	}
	if err := ValidateJanitorDatabaseContract(ctx, janitorPool); err != nil {
		t.Fatalf("ValidateJanitorDatabaseContract: %v", err)
	}
	store := NewStore(janitorPool)
	if err := store.VerifyDeploymentIdentity(ctx, "stage.telecrypt.io", "test"); err != nil {
		t.Fatalf("VerifyDeploymentIdentity: %v", err)
	}
}
