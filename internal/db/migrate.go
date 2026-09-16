package db

import (
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed janitor_migrations/*.sql
var migrationFiles embed.FS

const (
	janitorSchemaMigrationsTable = "schema_migrations"
	janitorDigestCursorTable     = "janitor_digest_cursor"
	janitorRunEventsTable        = "run_events"
	janitorDigestCursorMigration = "0001_janitor_digest_cursor.sql"
	janitorRunEventsMigration    = "0002_janitor_run_events.sql"
	janitorRemoveDryRunMigration = "0003_remove_dry_run.sql"
	janitorMigrationLockID       = int64(0x54454c4543525950)
)

type janitorRelation struct {
	kind  string
	owner string
}

var requiredJanitorRelations = [...]string{
	janitorSchemaMigrationsTable,
	janitorDigestCursorTable,
	janitorRunEventsTable,
}

// Migrate applies pending Janitor migrations in filename order. Unsupported history or required
// relations with the wrong kind or owner stop migration and need operator diagnosis.
func Migrate(ctx context.Context, pool *pgxpool.Pool) (migrationErr error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	// Serialize Janitor migration runners at the database so concurrent one-shot invocations are
	// safe; Cashier uses its own private-schema migration history and lock.
	if _, err := conn.Exec(ctx, `SELECT pg_catalog.pg_advisory_lock($1)`, janitorMigrationLockID); err != nil {
		acquireErr := fmt.Errorf("acquire migration lock: %w", err)
		if closeErr := discardPoolConn(conn); closeErr != nil {
			return errors.Join(acquireErr, fmt.Errorf("close discarded migration connection: %w", closeErr))
		}
		return acquireErr
	}
	defer func() {
		if releaseErr := releaseAdvisoryLock(conn, janitorMigrationLockID); releaseErr != nil {
			migrationErr = errors.Join(migrationErr, releaseErr)
		}
	}()

	var schemaReady bool
	if err := conn.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM pg_catalog.pg_namespace n
				JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner
				WHERE n.nspname = 'janitor' AND r.rolname = current_user
			)
	`).Scan(&schemaReady); err != nil {
		return fmt.Errorf("check janitor schema: %w", err)
	}
	if !schemaReady {
		return fmt.Errorf("janitor database requires a pre-created janitor schema owned by the current role")
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	if len(migrations) == 0 {
		return fmt.Errorf("no Janitor migrations found")
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	committed := false
	defer func() { rollbackMigration(tx, committed, &migrationErr) }()
	relations, err := readJanitorRelations(ctx, tx)
	if err != nil {
		return err
	}
	currentRole, err := currentDatabaseRole(ctx, tx)
	if err != nil {
		return err
	}
	if err := validateJanitorRelations(relations, currentRole, false); err != nil {
		return err
	}
	historyExists, historyRecords, err := readMigrationHistory(ctx, tx, relations)
	if err != nil {
		return err
	}
	if err := validateMigrationState(historyExists, historyRecords, relations, migrations); err != nil {
		return err
	}
	applied := make(map[string]struct{}, len(historyRecords))
	for _, record := range historyRecords {
		applied[record.version] = struct{}{}
	}
	if !historyExists {
		if _, err := tx.Exec(ctx, `
			CREATE TABLE janitor.schema_migrations (
				version TEXT PRIMARY KEY,
				sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
				applied_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now()
			)
		`); err != nil {
			return fmt.Errorf("create schema_migrations: %w", err)
		}
	}

	for _, migration := range migrations {
		if _, ok := applied[migration.name]; ok {
			continue
		}
		if _, err := tx.Exec(ctx, string(migration.sql)); err != nil {
			return fmt.Errorf("apply migration %s: %w", migration.name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO janitor.schema_migrations (version, sha256) VALUES ($1, $2)`, migration.name, migration.sha256,
		); err != nil {
			return fmt.Errorf("record migration %s: %w", migration.name, err)
		}
	}
	relations, err = readJanitorRelations(ctx, tx)
	if err != nil {
		return err
	}
	if err := validateJanitorRelations(relations, currentRole, true); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	committed = true
	return nil
}

type migration struct {
	name   string
	sql    []byte
	sha256 string
}

type migrationRecord struct {
	version string
	sha256  string
}

func rollbackMigration(tx pgx.Tx, committed bool, result *error) {
	rollbackCtx, cancel := boundedCleanupContext(context.Background())
	defer cancel()
	if rollbackErr := tx.Rollback(rollbackCtx); rollbackErr != nil && (!committed || !errors.Is(rollbackErr, pgx.ErrTxClosed)) {
		*result = errors.Join(*result, fmt.Errorf("rollback migration transaction: %w", rollbackErr))
	}
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFiles, "janitor_migrations")
	if err != nil {
		return nil, fmt.Errorf("read Janitor migrations dir: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, fmt.Errorf("Janitor migration namespace contains unexpected directory %q", entry.Name())
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	migrations := make([]migration, 0, len(names))
	for _, name := range names {
		sqlBytes, err := migrationFiles.ReadFile("janitor_migrations/" + name)
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", name, err)
		}
		digest := sha256.Sum256(sqlBytes)
		migrations = append(migrations, migration{name: name, sql: sqlBytes, sha256: fmt.Sprintf("%x", digest[:])})
	}
	return migrations, nil
}

func currentDatabaseRole(ctx context.Context, tx pgx.Tx) (string, error) {
	var role string
	if err := tx.QueryRow(ctx, `SELECT current_user`).Scan(&role); err != nil {
		return "", fmt.Errorf("read current database role: %w", err)
	}
	return role, nil
}

func readJanitorRelations(ctx context.Context, tx pgx.Tx) (map[string]janitorRelation, error) {
	relations := make(map[string]janitorRelation, len(requiredJanitorRelations))
	rows, err := tx.Query(ctx, `
		SELECT c.relname, c.relkind::pg_catalog.text, r.rolname
		FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
		WHERE n.nspname = 'janitor'
		  AND c.relkind NOT IN ('i', 'I')
		ORDER BY c.relname
	`)
	if err != nil {
		return nil, fmt.Errorf("inspect required Janitor relations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, kind, owner string
		if err := rows.Scan(&name, &kind, &owner); err != nil {
			return nil, fmt.Errorf("scan required Janitor relation: %w", err)
		}
		relations[name] = janitorRelation{kind: kind, owner: owner}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate required Janitor relations: %w", err)
	}
	return relations, nil
}

func validateJanitorRelations(relations map[string]janitorRelation, currentRole string, requireAll bool) error {
	for _, name := range requiredJanitorRelations {
		relation, exists := relations[name]
		if !exists {
			if requireAll {
				return fmt.Errorf("required Janitor relation %q is missing; operator diagnosis required", name)
			}
			continue
		}
		if relation.kind != "r" {
			return fmt.Errorf("Janitor schema object %q must be a table; operator diagnosis required", name)
		}
		if relation.owner != currentRole {
			return fmt.Errorf("Janitor relation %q is owned by %q, not current role %q; operator diagnosis required", name, relation.owner, currentRole)
		}
	}
	return nil
}

func readMigrationHistory(ctx context.Context, tx pgx.Tx, relations map[string]janitorRelation) (bool, []migrationRecord, error) {
	object, exists := relations[janitorSchemaMigrationsTable]
	if !exists {
		return false, nil, nil
	}
	if object.kind != "r" {
		return false, nil, fmt.Errorf("Janitor schema object %q must be a table", janitorSchemaMigrationsTable)
	}
	rows, err := tx.Query(ctx, `SELECT version, sha256 FROM janitor.schema_migrations ORDER BY applied_at, version`)
	if err != nil {
		return false, nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	records := make([]migrationRecord, 0)
	for rows.Next() {
		var record migrationRecord
		if err := rows.Scan(&record.version, &record.sha256); err != nil {
			return false, nil, fmt.Errorf("scan schema_migrations: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return false, nil, fmt.Errorf("iterate schema_migrations: %w", err)
	}
	return true, records, nil
}

func validateMigrationState(historyExists bool, historyRecords []migrationRecord, relations map[string]janitorRelation, migrations []migration) error {
	knownMigrations := make(map[string]string, len(migrations))
	for _, migration := range migrations {
		knownMigrations[migration.name] = migration.sha256
	}
	seenVersions := make(map[string]struct{}, len(historyRecords))
	for _, record := range historyRecords {
		expectedDigest, ok := knownMigrations[record.version]
		if !ok {
			return fmt.Errorf("unknown schema migration version %q; operator diagnosis required", record.version)
		}
		if record.sha256 != expectedDigest {
			return fmt.Errorf("migration %q has digest %q, expected %q; operator diagnosis required", record.version, record.sha256, expectedDigest)
		}
		if _, duplicate := seenVersions[record.version]; duplicate {
			return fmt.Errorf("duplicate schema migration version %q; operator diagnosis required", record.version)
		}
		seenVersions[record.version] = struct{}{}
	}
	for i, record := range historyRecords {
		if i >= len(migrations) || record.version != migrations[i].name {
			return fmt.Errorf("Janitor migration history is not the exact ordered stream; operator diagnosis required")
		}
	}
	_, digestApplied := seenVersions[janitorDigestCursorMigration]
	_, runEventsApplied := seenVersions[janitorRunEventsMigration]
	object, digestExists := relations[janitorDigestCursorTable]
	if digestApplied && !digestExists {
		return fmt.Errorf("migration %q is recorded but table %q is missing; operator diagnosis required", janitorDigestCursorMigration, janitorDigestCursorTable)
	}
	if digestExists && object.kind != "r" {
		return fmt.Errorf("Janitor schema object %q must be a table", janitorDigestCursorTable)
	}
	if digestExists && !digestApplied {
		return fmt.Errorf("table %q exists without migration %q; operator diagnosis required", janitorDigestCursorTable, janitorDigestCursorMigration)
	}
	runEventsObject, runEventsExists := relations[janitorRunEventsTable]
	if runEventsApplied && !runEventsExists {
		return fmt.Errorf("migration %q is recorded but table %q is missing; operator diagnosis required", janitorRunEventsMigration, janitorRunEventsTable)
	}
	if runEventsExists && runEventsObject.kind != "r" {
		return fmt.Errorf("Janitor schema object %q must be a table", janitorRunEventsTable)
	}
	if runEventsExists && !runEventsApplied {
		return fmt.Errorf("table %q exists without migration %q; operator diagnosis required", janitorRunEventsTable, janitorRunEventsMigration)
	}
	if runEventsApplied && !digestApplied {
		return fmt.Errorf("migration %q cannot be applied before %q; operator diagnosis required", janitorRunEventsMigration, janitorDigestCursorMigration)
	}
	if !historyExists && len(historyRecords) != 0 {
		return fmt.Errorf("schema migration history is inconsistent; operator diagnosis required")
	}
	return nil
}
