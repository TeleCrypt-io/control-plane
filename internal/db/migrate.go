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

// Migrate keeps only the small private state Janitor needs for its email cursor. Cashier owns
// billing and lifecycle facts; Janitor does not maintain an audit ledger or an invocation lock.
func Migrate(ctx context.Context, pool *pgxpool.Pool) (migrationErr error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	committed := false
	defer func() { rollbackMigration(tx, committed, &migrationErr) }()

	var schemaReady bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_namespace n
			JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner
			WHERE n.nspname = 'janitor' AND r.rolname = current_user
		)
	`).Scan(&schemaReady); err != nil {
		return fmt.Errorf("check Janitor schema: %w", err)
	}
	if !schemaReady {
		return fmt.Errorf("Janitor database requires a pre-created janitor schema owned by the current role")
	}
	if _, err := tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS janitor.schema_migrations (
			version TEXT PRIMARY KEY,
			sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
			applied_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now()
		)
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE janitor.schema_migrations IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return fmt.Errorf("lock schema_migrations: %w", err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	history, err := readMigrationHistory(ctx, tx)
	if err != nil {
		return err
	}
	if err := validateMigrationHistory(history, migrations); err != nil {
		return err
	}
	applied := make(map[string]struct{}, len(history))
	for _, record := range history {
		applied[record.version] = struct{}{}
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
	if rollbackErr := tx.Rollback(context.Background()); rollbackErr != nil && (!committed || !errors.Is(rollbackErr, pgx.ErrTxClosed)) {
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

func readMigrationHistory(ctx context.Context, tx pgx.Tx) ([]migrationRecord, error) {
	rows, err := tx.Query(ctx, `SELECT version, sha256 FROM janitor.schema_migrations ORDER BY applied_at, version`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	var records []migrationRecord
	for rows.Next() {
		var record migrationRecord
		if err := rows.Scan(&record.version, &record.sha256); err != nil {
			return nil, fmt.Errorf("scan schema_migrations: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schema_migrations: %w", err)
	}
	return records, nil
}

func validateMigrationHistory(history []migrationRecord, migrations []migration) error {
	known := make(map[string]string, len(migrations))
	for _, migration := range migrations {
		known[migration.name] = migration.sha256
	}
	seen := make(map[string]struct{}, len(history))
	for index, record := range history {
		want, ok := known[record.version]
		if !ok {
			return fmt.Errorf("unknown Janitor migration %q", record.version)
		}
		if want != record.sha256 {
			return fmt.Errorf("Janitor migration %q has changed", record.version)
		}
		if _, ok := seen[record.version]; ok {
			return fmt.Errorf("duplicate Janitor migration %q", record.version)
		}
		seen[record.version] = struct{}{}
		if index >= len(migrations) || migrations[index].name != record.version {
			return fmt.Errorf("Janitor migration history is out of order")
		}
	}
	return nil
}
