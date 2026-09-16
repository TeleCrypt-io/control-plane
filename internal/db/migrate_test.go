package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestValidateMigrationState(t *testing.T) {
	const version = janitorDigestCursorMigration
	const version2 = janitorRunEventsMigration
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	validRelations := map[string]string{
		janitorSchemaMigrationsTable: "r",
		janitorDigestCursorTable:     "r",
		janitorRunEventsTable:        "r",
	}
	tests := []struct {
		name          string
		historyExists bool
		history       []string
		relations     map[string]string
		wantError     string
	}{
		{name: "fresh schema", relations: map[string]string{}},
		{name: "empty history", historyExists: true, relations: map[string]string{janitorSchemaMigrationsTable: "r"}},
		{name: "applied current migration", historyExists: true, history: []string{version, version2}, relations: validRelations},
		{name: "unknown migration history", historyExists: true, history: []string{"0001_unknown_history.sql"}, relations: map[string]string{janitorSchemaMigrationsTable: "r"}, wantError: "unknown schema migration"},
		{name: "duplicate history", historyExists: true, history: []string{version, version}, relations: validRelations, wantError: "duplicate schema migration"},
		{name: "recorded migration without table", historyExists: true, history: []string{version}, relations: map[string]string{janitorSchemaMigrationsTable: "r"}, wantError: "is recorded but table"},
		{name: "table without history", relations: map[string]string{janitorDigestCursorTable: "r"}, wantError: "exists without migration"},
		{name: "view in private schema", relations: map[string]string{janitorDigestCursorTable: "v"}, wantError: "must be a table"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMigrationState(tt.historyExists, testMigrationRecords(tt.history, digest), testRelationObjects(tt.relations), []migration{{name: version, sha256: digest}, {name: version2, sha256: digest}})
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("validateMigrationState() = %v, want success", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("validateMigrationState() = %v, want error containing %q", err, tt.wantError)
			}
		})
	}
}

func testMigrationRecords(versions []string, digest string) []migrationRecord {
	records := make([]migrationRecord, 0, len(versions))
	for _, version := range versions {
		records = append(records, migrationRecord{version: version, sha256: digest})
	}
	return records
}

func testRelationObjects(objects map[string]string) map[string]janitorRelation {
	result := make(map[string]janitorRelation, len(objects))
	for name, kind := range objects {
		result[name] = janitorRelation{kind: kind, owner: "janitor"}
	}
	return result
}

func TestValidateMigrationStateRejectsChangedMigrationDigest(t *testing.T) {
	err := validateMigrationState(
		true,
		[]migrationRecord{{version: janitorDigestCursorMigration, sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		map[string]janitorRelation{
			janitorSchemaMigrationsTable: {kind: "r"},
			janitorDigestCursorTable:     {kind: "r"},
		},
		[]migration{{name: janitorDigestCursorMigration, sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
	)
	if err == nil || !strings.Contains(err.Error(), "has digest") {
		t.Fatalf("validateMigrationState() = %v, want digest drift error", err)
	}
}

func TestLoadJanitorMigrationsUsesChecksummedSources(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("loadMigrations returned no migrations")
	}
	for i, migration := range migrations {
		if i > 0 && migration.name <= migrations[i-1].name {
			t.Fatalf("migrations are not sorted: %q follows %q", migration.name, migrations[i-1].name)
		}
		if len(migration.sha256) != 64 {
			t.Fatalf("migration %d %q has invalid SHA-256 digest %q", i, migration.name, migration.sha256)
		}
	}
}

func TestValidateJanitorRelations(t *testing.T) {
	valid := map[string]janitorRelation{
		janitorSchemaMigrationsTable: {kind: "r", owner: "janitor"},
		janitorDigestCursorTable:     {kind: "r", owner: "janitor"},
		janitorRunEventsTable:        {kind: "r", owner: "janitor"},
	}
	if err := validateJanitorRelations(valid, "janitor", true); err != nil {
		t.Fatalf("validateJanitorRelations rejected required tables: %v", err)
	}
	tests := []struct {
		name      string
		relations map[string]janitorRelation
		want      string
	}{
		{name: "missing required", relations: map[string]janitorRelation{janitorSchemaMigrationsTable: {kind: "r", owner: "janitor"}}, want: "is missing"},
		{name: "wrong kind", relations: map[string]janitorRelation{janitorSchemaMigrationsTable: {kind: "v", owner: "janitor"}}, want: "must be a table"},
		{name: "wrong owner", relations: map[string]janitorRelation{janitorSchemaMigrationsTable: {kind: "r", owner: "other"}}, want: "not current role"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateJanitorRelations(tt.relations, "janitor", true); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateJanitorRelations() = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestMigrateUsesFreshJanitorSchema(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres test")
	}
	ctx := context.Background()
	pool, err := OpenJanitorPool(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenJanitorPool: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS janitor CASCADE`); err != nil {
		t.Fatalf("drop janitor schema: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE SCHEMA janitor`); err != nil {
		t.Fatalf("create janitor schema: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	for _, table := range []string{"janitor_digest_cursor", "run_events", "schema_migrations"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema = 'janitor' AND table_name = $1)`, table).Scan(&exists); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if !exists {
			t.Errorf("expected table %q after Migrate", table)
		}
	}
	var dryRunExists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema = 'janitor' AND table_name = 'run_events' AND column_name = 'dry_run')`).Scan(&dryRunExists); err != nil {
		t.Fatalf("check historical dry_run column: %v", err)
	}
	if !dryRunExists {
		t.Fatal("historical dry_run column was removed from Janitor audit table")
	}
	var dryRunDefault *string
	if err := pool.QueryRow(ctx, `SELECT column_default FROM information_schema.columns WHERE table_schema = 'janitor' AND table_name = 'run_events' AND column_name = 'dry_run'`).Scan(&dryRunDefault); err != nil {
		t.Fatalf("check historical dry_run default: %v", err)
	}
	if dryRunDefault == nil || !strings.Contains(strings.ToLower(*dryRunDefault), "false") {
		t.Fatalf("dry_run default = %v, want false", dryRunDefault)
	}
	var migrationCount int
	if err := pool.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM janitor.schema_migrations`).Scan(&migrationCount); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if migrationCount != 4 {
		t.Fatalf("migration count = %d, want 4", migrationCount)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

func TestMigratePreservesHistoricalPreviewAudit(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres migration upgrade test")
	}
	ctx := context.Background()
	pool, err := OpenJanitorPool(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenJanitorPool: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS janitor CASCADE; CREATE SCHEMA janitor`); err != nil {
		t.Fatalf("create Janitor schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS janitor CASCADE`)
	})

	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migrations) != 4 {
		t.Fatalf("migration count = %d, want 4", len(migrations))
	}
	if _, err := pool.Exec(ctx, string(migrations[0].sql)); err != nil {
		t.Fatalf("apply 0001 migration: %v", err)
	}
	if _, err := pool.Exec(ctx, string(migrations[1].sql)); err != nil {
		t.Fatalf("apply 0002 migration: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE janitor.schema_migrations (
			version TEXT PRIMARY KEY,
			sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
			applied_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now()
		)`); err != nil {
		t.Fatalf("create legacy migration history: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO janitor.schema_migrations (version, sha256, applied_at)
		VALUES ($1, $2, '2026-01-01T00:00:00Z'), ($3, $4, '2026-01-01T00:00:01Z')
	`, migrations[0].name, migrations[0].sha256, migrations[1].name, migrations[1].sha256); err != nil {
		t.Fatalf("insert legacy migration history: %v", err)
	}
	eventID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO janitor.run_events
		(event_id, run_id, event_kind, status, outcome, reason, server_name, billing_environment,
		 dry_run, considered, skipped, locked_or_would_lock, failures, notification_status, labels)
		VALUES ($1, $2, 'finished', 'succeeded', 'dry_run', 'would_disable', 'stage.telecrypt.io', 'test',
		 TRUE, 3, 1, 2, 0, 'not_attempted', ARRAY['mas_users']::TEXT[])
	`, eventID, uuid.New()); err != nil {
		t.Fatalf("insert historical preview event: %v", err)
	}

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("upgrade Migrate: %v", err)
	}
	var outcome, reason string
	var dryRun bool
	if err := pool.QueryRow(ctx, `SELECT outcome, reason, dry_run FROM janitor.run_events WHERE event_id = $1`, eventID).Scan(&outcome, &reason, &dryRun); err != nil {
		t.Fatalf("read historical preview event: %v", err)
	}
	if outcome != "dry_run" || reason != "would_disable" || !dryRun {
		t.Fatalf("historical preview event changed to outcome=%q reason=%q dry_run=%t", outcome, reason, dryRun)
	}
	newEventID := uuid.New()
	if err := NewStore(pool).InsertRunEvent(ctx, RunEvent{
		EventID: newEventID, RunID: uuid.New(), EventKind: "finished", Status: "succeeded",
		Outcome: "success", Reason: "disabled", ServerName: "stage.telecrypt.io", BillingEnvironment: "test",
		Considered: 1, LockedOrWouldLock: 1, NotificationStatus: "not_attempted", Labels: []string{"lock"},
	}); err != nil {
		t.Fatalf("insert new real test-profile event: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT dry_run FROM janitor.run_events WHERE event_id = $1`, newEventID).Scan(&dryRun); err != nil {
		t.Fatalf("read new real test-profile event: %v", err)
	}
	if dryRun {
		t.Fatal("new real test-profile event was recorded as dry_run")
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("second upgraded Migrate: %v", err)
	}
}

func TestMigrateRejectsJanitorSchemaOwnedByAnotherRole(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres test")
	}
	ctx := context.Background()
	rawPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer rawPool.Close()

	if _, err := rawPool.Exec(ctx, `DROP SCHEMA IF EXISTS janitor CASCADE`); err != nil {
		t.Fatalf("drop janitor schema: %v", err)
	}
	if _, err := rawPool.Exec(ctx, `DROP ROLE IF EXISTS janitor_migration_other_owner_test`); err != nil {
		t.Fatalf("drop previous test role: %v", err)
	}
	if _, err := rawPool.Exec(ctx, `CREATE ROLE janitor_migration_other_owner_test NOLOGIN`); err != nil {
		t.Fatalf("create test role: %v", err)
	}
	t.Cleanup(func() {
		_, _ = rawPool.Exec(context.Background(), `DROP SCHEMA IF EXISTS janitor CASCADE`)
		_, _ = rawPool.Exec(context.Background(), `DROP ROLE IF EXISTS janitor_migration_other_owner_test`)
	})
	if _, err := rawPool.Exec(ctx, `CREATE SCHEMA janitor AUTHORIZATION janitor_migration_other_owner_test`); err != nil {
		t.Fatalf("create janitor schema with wrong owner: %v", err)
	}

	pool, err := OpenJanitorPool(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenJanitorPool: %v", err)
	}
	defer pool.Close()
	if err := Migrate(ctx, pool); err == nil || !strings.Contains(err.Error(), "pre-created janitor schema owned by the current role") {
		t.Fatalf("Migrate with wrong schema owner = %v, want ownership error", err)
	}
}

func TestMigrateRejectsUnknownHistoryAndLeavesFreshObjectsUncreated(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres test")
	}
	ctx := context.Background()
	pool, err := OpenJanitorPool(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenJanitorPool: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS janitor CASCADE; CREATE SCHEMA janitor; CREATE TABLE janitor.schema_migrations (version TEXT PRIMARY KEY, sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'), applied_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now()); INSERT INTO janitor.schema_migrations (version, sha256) VALUES ('0001_unknown_history.sql', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')`); err != nil {
		t.Fatalf("create unknown migration history: %v", err)
	}
	if err := Migrate(ctx, pool); err == nil || !strings.Contains(err.Error(), "unknown schema migration version") {
		t.Fatalf("Migrate with renamed history = %v, want unknown-history error", err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema = 'janitor' AND table_name = 'janitor_digest_cursor')`).Scan(&exists); err != nil {
		t.Fatalf("check digest cursor: %v", err)
	}
	if exists {
		t.Fatal("unknown history created janitor_digest_cursor")
	}
}

func TestMigrateRejectsLegacyLockerStateInsteadOfTreatingSchemaAsFresh(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres test")
	}
	ctx := context.Background()
	pool, err := OpenJanitorPool(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenJanitorPool: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS janitor CASCADE; CREATE SCHEMA janitor; CREATE TABLE janitor.locker_state (key TEXT PRIMARY KEY, value TIMESTAMPTZ NOT NULL)`); err != nil {
		t.Fatalf("create legacy Janitor state: %v", err)
	}
	if err := Migrate(ctx, pool); err == nil || !strings.Contains(err.Error(), "unexpected Janitor schema relation") {
		t.Fatalf("Migrate with legacy locker_state = %v, want legacy-object rejection", err)
	}
}

func TestMigrateRejectsChangedMigrationDigest(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres test")
	}
	ctx := context.Background()
	pool, err := OpenJanitorPool(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenJanitorPool: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `
		DROP SCHEMA IF EXISTS janitor CASCADE;
		CREATE SCHEMA janitor;
		CREATE TABLE janitor.schema_migrations (
			version TEXT PRIMARY KEY,
			sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
			applied_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now()
		);
		CREATE TABLE janitor.janitor_digest_cursor (
			singleton BOOLEAN PRIMARY KEY CHECK (singleton = TRUE),
			created_at TIMESTAMPTZ NOT NULL,
			email_id TEXT NOT NULL
		);
		INSERT INTO janitor.schema_migrations (version, sha256)
		VALUES ('0001_janitor_digest_cursor.sql', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
	`); err != nil {
		t.Fatalf("create changed migration history: %v", err)
	}
	if err := Migrate(ctx, pool); err == nil || !strings.Contains(err.Error(), "has digest") {
		t.Fatalf("Migrate with changed migration digest = %v, want digest-drift error", err)
	}
}

func openMigratedJanitorFixture(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres test")
	}
	ctx := context.Background()
	pool, err := OpenJanitorPool(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenJanitorPool: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS janitor CASCADE; CREATE SCHEMA janitor`); err != nil {
		t.Fatalf("create Janitor schema: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("initial Janitor migration: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS janitor CASCADE`)
	})
	return ctx, pool
}

func TestMigrateAcceptsAdditiveJanitorObjects(t *testing.T) {
	ctx, pool := openMigratedJanitorFixture(t)
	if _, err := pool.Exec(ctx, `
		ALTER TABLE janitor.janitor_digest_cursor ADD COLUMN local_note TEXT;
		CREATE INDEX janitor_digest_cursor_local_note_idx ON janitor.janitor_digest_cursor (local_note);
		ALTER TABLE janitor.run_events ADD COLUMN local_note TEXT;
		CREATE INDEX janitor_run_events_local_note_idx ON janitor.run_events (local_note);
		CREATE FUNCTION janitor.local_helper() RETURNS INTEGER LANGUAGE SQL IMMUTABLE AS $$ SELECT 1 $$;
		CREATE DOMAIN janitor.local_label AS TEXT CHECK (VALUE <> '')
	`); err != nil {
		t.Fatalf("add local Janitor columns, indexes, and helper objects: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate with additive schema objects: %v", err)
	}
	var localObjectsExist bool
	if err := pool.QueryRow(ctx, `SELECT to_regprocedure('janitor.local_helper()') IS NOT NULL AND to_regtype('janitor.local_label') IS NOT NULL`).Scan(&localObjectsExist); err != nil {
		t.Fatalf("check additive Janitor helper objects: %v", err)
	}
	if !localObjectsExist {
		t.Fatal("migration removed an additive Janitor helper object")
	}

	store := NewStore(pool)
	cursor := DigestCursor{CreatedAt: time.Now().UTC().Truncate(time.Microsecond), EmailID: "01J00000000000000000000000"}
	if err := store.SetJanitorDigestCursor(ctx, cursor); err != nil {
		t.Fatalf("set digest cursor: %v", err)
	}
	gotCursor, exists, err := store.JanitorDigestCursor(ctx)
	if err != nil {
		t.Fatalf("read digest cursor: %v", err)
	}
	if !exists || !gotCursor.CreatedAt.Equal(cursor.CreatedAt) || gotCursor.EmailID != cursor.EmailID {
		t.Fatalf("digest cursor = (%+v, %t), want (%+v, true)", gotCursor, exists, cursor)
	}
	eventID := uuid.New()
	if err := store.InsertRunEvent(ctx, RunEvent{
		EventID: eventID, RunID: uuid.New(), EventKind: "finished", Status: "succeeded",
		Outcome: "success", Reason: "no_eligible_accounts", ServerName: "stage.telecrypt.io",
		BillingEnvironment: "test", NotificationStatus: "not_attempted", Labels: []string{"database"},
	}); err != nil {
		t.Fatalf("insert run event: %v", err)
	}
}

func TestMigrateUpgradesEverySupportedPrefix(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres migration test")
	}
	ctx := context.Background()
	pool, err := OpenJanitorPool(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenJanitorPool: %v", err)
	}
	defer pool.Close()
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}

	for prefix := 0; prefix <= len(migrations); prefix++ {
		t.Run(fmt.Sprintf("prefix_%d", prefix), func(t *testing.T) {
			if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS janitor CASCADE; CREATE SCHEMA janitor`); err != nil {
				t.Fatalf("reset Janitor schema: %v", err)
			}
			t.Cleanup(func() {
				_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS janitor CASCADE`)
			})

			appliedAt := make([]time.Time, prefix)
			for i := 0; i < prefix; i++ {
				if _, err := pool.Exec(ctx, string(migrations[i].sql)); err != nil {
					t.Fatalf("apply %s: %v", migrations[i].name, err)
				}
			}
			if prefix > 0 {
				if _, err := pool.Exec(ctx, `CREATE TABLE janitor.schema_migrations (
					version TEXT PRIMARY KEY,
					sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
					applied_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now()
				)`); err != nil {
					t.Fatalf("create migration history: %v", err)
				}
				for i := 0; i < prefix; i++ {
					appliedAt[i] = time.Date(2026, time.January, i+1, 12, 0, 0, 0, time.UTC)
					if _, err := pool.Exec(ctx, `INSERT INTO janitor.schema_migrations (version, sha256, applied_at) VALUES ($1, $2, $3)`, migrations[i].name, migrations[i].sha256, appliedAt[i]); err != nil {
						t.Fatalf("record %s: %v", migrations[i].name, err)
					}
				}
			}
			if prefix >= 1 {
				if _, err := pool.Exec(ctx, `INSERT INTO janitor.janitor_digest_cursor (singleton, created_at, email_id) VALUES (TRUE, '2026-01-01T00:00:00Z', '01J00000000000000000000000')`); err != nil {
					t.Fatalf("seed digest cursor: %v", err)
				}
			}
			if prefix >= 2 {
				if _, err := pool.Exec(ctx, `INSERT INTO janitor.run_events
					(event_id, run_id, event_kind, status, outcome, reason, server_name, billing_environment,
					 dry_run, considered, skipped, locked_or_would_lock, failures, notification_status, labels)
					VALUES ($1, $2, 'finished', 'succeeded', 'dry_run', 'would_disable', 'stage.telecrypt.io', 'test',
					 TRUE, 3, 1, 2, 0, 'not_attempted', ARRAY['mas_users']::TEXT[])`, uuid.New(), uuid.New()); err != nil {
					t.Fatalf("seed historical preview event: %v", err)
				}
			}

			if err := Migrate(ctx, pool); err != nil {
				t.Fatalf("Migrate prefix %d: %v", prefix, err)
			}
			var migrationCount int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM janitor.schema_migrations`).Scan(&migrationCount); err != nil {
				t.Fatalf("count migration history: %v", err)
			}
			if migrationCount != len(migrations) {
				t.Fatalf("migration count = %d, want %d", migrationCount, len(migrations))
			}
			for i := 0; i < prefix; i++ {
				var got time.Time
				if err := pool.QueryRow(ctx, `SELECT applied_at FROM janitor.schema_migrations WHERE version = $1`, migrations[i].name).Scan(&got); err != nil {
					t.Fatalf("read applied_at for %s: %v", migrations[i].name, err)
				}
				if !got.Equal(appliedAt[i]) {
					t.Fatalf("applied_at for %s = %s, want unchanged %s", migrations[i].name, got, appliedAt[i])
				}
			}
			if prefix >= 1 {
				var emailID string
				if err := pool.QueryRow(ctx, `SELECT email_id FROM janitor.janitor_digest_cursor WHERE singleton`).Scan(&emailID); err != nil {
					t.Fatalf("read digest cursor: %v", err)
				}
				if emailID != "01J00000000000000000000000" {
					t.Fatalf("digest cursor email_id = %q", emailID)
				}
			}
			if prefix >= 2 {
				var previewRows int
				if err := pool.QueryRow(ctx, `SELECT count(*) FROM janitor.run_events WHERE outcome='dry_run' AND dry_run`).Scan(&previewRows); err != nil {
					t.Fatalf("read historical preview event: %v", err)
				}
				if previewRows != 1 {
					t.Fatalf("historical preview rows = %d, want 1", previewRows)
				}
			}
		})
	}
}

func TestMigrateRollsBackFailedMigrationRecordAndCanRetry(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres migration test")
	}
	ctx := context.Background()
	pool, err := OpenJanitorPool(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenJanitorPool: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `
		DROP SCHEMA IF EXISTS janitor CASCADE;
		DROP FUNCTION IF EXISTS public.fail_janitor_history_insert_migrate_test();
		CREATE SCHEMA janitor;
		CREATE TABLE janitor.schema_migrations (
			version TEXT PRIMARY KEY,
			sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
			applied_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now()
		);
		CREATE FUNCTION public.fail_janitor_history_insert_migrate_test() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test migration history failure'; END $$;
		CREATE TRIGGER fail_janitor_history_insert BEFORE INSERT ON janitor.schema_migrations
		FOR EACH ROW EXECUTE FUNCTION public.fail_janitor_history_insert_migrate_test()
	`); err != nil {
		t.Fatalf("prepare migration failure: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS janitor CASCADE`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS public.fail_janitor_history_insert_migrate_test()`)
	})

	if err := Migrate(ctx, pool); err == nil || !strings.Contains(err.Error(), "record migration") {
		t.Fatalf("Migrate with failing history insert = %v, want migration-record failure", err)
	}
	var cursorExists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('janitor.janitor_digest_cursor') IS NOT NULL`).Scan(&cursorExists); err != nil {
		t.Fatalf("check rolled-back digest cursor: %v", err)
	}
	var historyCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM janitor.schema_migrations`).Scan(&historyCount); err != nil {
		t.Fatalf("check rolled-back history: %v", err)
	}
	if cursorExists || historyCount != 0 {
		t.Fatalf("failed migration left cursor=%t and history rows=%d", cursorExists, historyCount)
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER fail_janitor_history_insert ON janitor.schema_migrations`); err != nil {
		t.Fatalf("remove injected failure: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("retry migration after fixing injected failure: %v", err)
	}
}

func TestMigrateLockCancellationAndConcurrentStarts(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres migration test")
	}
	ctx := context.Background()
	pool, err := OpenJanitorPool(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenJanitorPool: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS janitor CASCADE; CREATE SCHEMA janitor`); err != nil {
		t.Fatalf("create Janitor schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS janitor CASCADE`)
	})
	held, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire lock connection: %v", err)
	}
	warm, err := pool.Acquire(ctx)
	if err != nil {
		held.Release()
		t.Fatalf("warm migration connection pool: %v", err)
	}
	warm.Release()
	if _, err := held.Exec(ctx, `SELECT pg_catalog.pg_advisory_lock($1)`, janitorMigrationLockID); err != nil {
		held.Release()
		t.Fatalf("hold migration lock: %v", err)
	}
	cancelCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	if err := Migrate(cancelCtx, pool); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Migrate while lock is held = %v, want deadline error", err)
	}
	if _, err := held.Exec(ctx, `SELECT pg_catalog.pg_advisory_unlock($1)`, janitorMigrationLockID); err != nil {
		held.Release()
		t.Fatalf("release migration lock: %v", err)
	}
	held.Release()

	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			results <- Migrate(ctx, pool)
		}()
	}
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent Migrate: %v", err)
		}
	}
	var migrationCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM janitor.schema_migrations`).Scan(&migrationCount); err != nil {
		t.Fatalf("count concurrent migration records: %v", err)
	}
	if migrationCount != 4 {
		t.Fatalf("concurrent migration records = %d, want 4", migrationCount)
	}
}
