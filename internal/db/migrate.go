package db

import (
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"sort"
	"strings"
	"unicode"

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
)

var expectedJanitorMigrationNames = []string{
	janitorDigestCursorMigration,
	janitorRunEventsMigration,
}

type janitorRelation struct {
	kind  string
	owner string
}

var requiredJanitorRelations = [...]string{
	janitorSchemaMigrationsTable,
	janitorDigestCursorTable,
	janitorRunEventsTable,
}

// Migrate applies the fresh Janitor schema in filename order. The database schema is deliberately
// not a compatibility surface: an old history row or a required relation with the wrong kind or
// owner fails closed and requires a manual reset before a new release can run.
func Migrate(ctx context.Context, pool *pgxpool.Pool) (migrationErr error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	// Serialize Janitor migration runners at the database so concurrent one-shot invocations are
	// safe; Cashier uses its own private-schema migration history and lock.
	const migrationLockID int64 = 0x54454c4543525950
	if _, err := conn.Exec(ctx, `SELECT pg_catalog.pg_advisory_lock($1)`, migrationLockID); err != nil {
		acquireErr := fmt.Errorf("acquire migration lock: %w", err)
		if closeErr := discardPoolConn(conn); closeErr != nil {
			return errors.Join(acquireErr, fmt.Errorf("close discarded migration connection: %w", closeErr))
		}
		return acquireErr
	}
	defer func() {
		if releaseErr := releaseAdvisoryLock(conn, migrationLockID); releaseErr != nil {
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
	if err := validateJanitorNamespaceObjects(ctx, tx); err != nil {
		return err
	}

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
	if err := validateJanitorTableShapes(ctx, tx, relations, false); err != nil {
		return err
	}

	applied := make(map[string]string, len(historyRecords))
	for _, record := range historyRecords {
		applied[record.version] = record.sha256
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
		if recordedDigest, ok := applied[migration.name]; ok {
			if recordedDigest != migration.sha256 {
				return fmt.Errorf("migration %q has digest %q, expected %q; manual reset required", migration.name, recordedDigest, migration.sha256)
			}
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
	if err := validateJanitorNamespaceObjects(ctx, tx); err != nil {
		return err
	}
	if err := validateJanitorRelations(relations, currentRole, true); err != nil {
		return err
	}
	if err := validateJanitorTableShapes(ctx, tx, relations, true); err != nil {
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

// validateJanitorNamespaceObjects closes the gaps in pg_class-only relation inspection. A
// pre-created routine, user-defined scalar type, or collation is still state in the schema even
// when no table relation remains; accepting one would make the "fresh" migration path
// non-deterministic. Table row types and their generated array types are tied to the two allowed
// tables and therefore remain valid.
func validateJanitorNamespaceObjects(ctx context.Context, tx pgx.Tx) error {
	var unexpected bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM pg_catalog.pg_proc p
			JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
			WHERE n.nspname = 'janitor'
			UNION ALL
			SELECT 1
			FROM pg_catalog.pg_type t
			JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
			WHERE n.nspname = 'janitor' AND t.typtype <> 'p' AND t.typrelid = 0 AND t.typelem = 0
			UNION ALL
			SELECT 1
			FROM pg_catalog.pg_collation c
			JOIN pg_catalog.pg_namespace n ON n.oid = c.collnamespace
			WHERE n.nspname = 'janitor'
		)`).Scan(&unexpected)
	if err != nil {
		return fmt.Errorf("inspect Janitor schema namespace objects: %w", err)
	}
	if unexpected {
		return fmt.Errorf("unexpected Janitor schema object; manual reset required")
	}
	return nil
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
	if err := validateJanitorMigrationNames(names); err != nil {
		return nil, err
	}
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

func validateJanitorMigrationNames(names []string) error {
	if !reflect.DeepEqual(names, expectedJanitorMigrationNames) {
		return fmt.Errorf("Janitor migration namespace must contain only the exact ordered 0001 and 0002 migrations")
	}
	return nil
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
	for name := range relations {
		if name != janitorSchemaMigrationsTable && name != janitorDigestCursorTable && name != janitorRunEventsTable {
			return fmt.Errorf("unexpected Janitor schema relation %q; manual reset required", name)
		}
	}
	for _, name := range requiredJanitorRelations {
		relation, exists := relations[name]
		if !exists {
			if requireAll {
				return fmt.Errorf("required Janitor relation %q is missing; manual reset required", name)
			}
			continue
		}
		if relation.kind != "r" {
			return fmt.Errorf("Janitor schema object %q must be a table; manual reset required", name)
		}
		if relation.owner != currentRole {
			return fmt.Errorf("Janitor relation %q is owned by %q, not current role %q; manual reset required", name, relation.owner, currentRole)
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
	for name := range relations {
		if name != janitorSchemaMigrationsTable && name != janitorDigestCursorTable && name != janitorRunEventsTable {
			return fmt.Errorf("unexpected Janitor schema relation %q; manual reset required", name)
		}
	}
	knownMigrations := make(map[string]string, len(migrations))
	for _, migration := range migrations {
		knownMigrations[migration.name] = migration.sha256
	}
	seenVersions := make(map[string]struct{}, len(historyRecords))
	for _, record := range historyRecords {
		expectedDigest, ok := knownMigrations[record.version]
		if !ok {
			return fmt.Errorf("unknown schema migration version %q; manual reset required", record.version)
		}
		if record.sha256 != expectedDigest {
			return fmt.Errorf("migration %q has digest %q, expected %q; manual reset required", record.version, record.sha256, expectedDigest)
		}
		if _, duplicate := seenVersions[record.version]; duplicate {
			return fmt.Errorf("duplicate schema migration version %q; manual reset required", record.version)
		}
		seenVersions[record.version] = struct{}{}
	}
	for i, record := range historyRecords {
		if i >= len(migrations) || record.version != migrations[i].name {
			return fmt.Errorf("Janitor migration history is not the exact ordered stream; manual reset required")
		}
	}
	_, digestApplied := seenVersions[janitorDigestCursorMigration]
	_, runEventsApplied := seenVersions[janitorRunEventsMigration]
	object, digestExists := relations[janitorDigestCursorTable]
	if digestApplied && !digestExists {
		return fmt.Errorf("migration %q is recorded but table %q is missing; manual reset required", janitorDigestCursorMigration, janitorDigestCursorTable)
	}
	if digestExists && object.kind != "r" {
		return fmt.Errorf("Janitor schema object %q must be a table", janitorDigestCursorTable)
	}
	if digestExists && !digestApplied {
		return fmt.Errorf("table %q exists without migration %q; manual reset required", janitorDigestCursorTable, janitorDigestCursorMigration)
	}
	runEventsObject, runEventsExists := relations[janitorRunEventsTable]
	if runEventsApplied && !runEventsExists {
		return fmt.Errorf("migration %q is recorded but table %q is missing; manual reset required", janitorRunEventsMigration, janitorRunEventsTable)
	}
	if runEventsExists && runEventsObject.kind != "r" {
		return fmt.Errorf("Janitor schema object %q must be a table", janitorRunEventsTable)
	}
	if runEventsExists && !runEventsApplied {
		return fmt.Errorf("table %q exists without migration %q; manual reset required", janitorRunEventsTable, janitorRunEventsMigration)
	}
	if runEventsApplied && !digestApplied {
		return fmt.Errorf("migration %q cannot be applied before %q; manual reset required", janitorRunEventsMigration, janitorDigestCursorMigration)
	}
	if !historyExists && len(historyRecords) != 0 {
		return fmt.Errorf("schema migration history is inconsistent; manual reset required")
	}
	return nil
}

type janitorColumnSpec struct {
	name     string
	typeName string
	notNull  bool
}

type janitorCheckSpec struct {
	columns    []string
	definition string
}

type janitorIndexSpec struct {
	name    string
	table   string
	columns []string
	unique  bool
	primary bool
	valid   bool
	live    bool
}

var janitorTableSpecs = map[string]struct {
	columns    []janitorColumnSpec
	primaryKey string
	checks     []janitorCheckSpec
}{
	janitorSchemaMigrationsTable: {
		columns: []janitorColumnSpec{
			{name: "version", typeName: "text", notNull: true},
			{name: "sha256", typeName: "text", notNull: true},
			{name: "applied_at", typeName: "timestamp with time zone", notNull: true},
		},
		primaryKey: "version",
		checks: []janitorCheckSpec{
			janitorCheckSpecFor(`CHECK ((sha256 ~ '^[0-9a-f]{64}$'::text))`, "sha256"),
		},
	},
	janitorDigestCursorTable: {
		columns: []janitorColumnSpec{
			{name: "singleton", typeName: "boolean", notNull: true},
			{name: "created_at", typeName: "timestamp with time zone", notNull: true},
			{name: "email_id", typeName: "text", notNull: true},
		},
		primaryKey: "singleton",
		checks: []janitorCheckSpec{
			janitorCheckSpecFor(`CHECK ((singleton = true))`, "singleton"),
		},
	},
	janitorRunEventsTable: {
		columns: []janitorColumnSpec{
			{name: "event_id", typeName: "uuid", notNull: true},
			{name: "run_id", typeName: "uuid", notNull: true},
			{name: "occurred_at", typeName: "timestamp with time zone", notNull: true},
			{name: "event_kind", typeName: "text", notNull: true},
			{name: "status", typeName: "text", notNull: true},
			{name: "outcome", typeName: "text", notNull: true},
			{name: "reason", typeName: "text", notNull: true},
			{name: "server_name", typeName: "text", notNull: true},
			{name: "billing_environment", typeName: "text", notNull: true},
			{name: "dry_run", typeName: "boolean", notNull: true},
			{name: "considered", typeName: "bigint", notNull: true},
			{name: "skipped", typeName: "bigint", notNull: true},
			{name: "locked_or_would_lock", typeName: "bigint", notNull: true},
			{name: "failures", typeName: "bigint", notNull: true},
			{name: "notification_status", typeName: "text", notNull: true},
			{name: "labels", typeName: "text[]", notNull: true},
		},
		primaryKey: "event_id",
		// The migration SQL owns the detailed enum/state checks. Column, owner, and primary-key
		// validation remains here; avoiding a brittle catalog-rendering duplicate keeps upgrades
		// stable across supported PostgreSQL minor releases.
		checks: nil,
	},
}

func janitorCheckSpecFor(definition string, columns ...string) janitorCheckSpec {
	return janitorCheckSpec{columns: columns, definition: normalizeCatalogDefinition(definition)}
}

var janitorIndexSpecs = []janitorIndexSpec{
	{
		name:    "schema_migrations_pkey",
		table:   janitorSchemaMigrationsTable,
		columns: []string{"version"},
		unique:  true,
		primary: true,
		valid:   true,
		live:    true,
	},
	{
		name:    "janitor_digest_cursor_pkey",
		table:   janitorDigestCursorTable,
		columns: []string{"singleton"},
		unique:  true,
		primary: true,
		valid:   true,
		live:    true,
	},
	{
		name:    "run_events_pkey",
		table:   janitorRunEventsTable,
		columns: []string{"event_id"},
		unique:  true,
		primary: true,
		valid:   true,
		live:    true,
	},
}

type janitorQueryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// validateJanitorTableShapes checks the small private schema contract in addition to relation
// names, kinds, and owners. Migration history proves which SQL bytes were intended; these catalog
// checks prove that same-named pre-existing objects still have the columns and invariants the
// runtime store relies on.
func validateJanitorTableShapes(ctx context.Context, conn janitorQueryer, relations map[string]janitorRelation, requireAll bool) error {
	for tableName, spec := range janitorTableSpecs {
		if _, exists := relations[tableName]; !exists {
			if requireAll {
				return fmt.Errorf("required Janitor table %q is missing; manual reset required", tableName)
			}
			continue
		}
		if err := validateJanitorTableColumns(ctx, conn, tableName, spec.columns); err != nil {
			return err
		}
		if err := validateJanitorPrimaryKey(ctx, conn, tableName, spec.primaryKey); err != nil {
			return err
		}
		if spec.checks != nil {
			if err := validateJanitorCheckConstraints(ctx, conn, tableName, spec.checks); err != nil {
				return err
			}
		}
	}
	return validateJanitorIndexes(ctx, conn, relations, requireAll)
}

func validateJanitorTableColumns(ctx context.Context, conn janitorQueryer, tableName string, expected []janitorColumnSpec) error {
	rows, err := conn.Query(ctx, `
		SELECT a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnotnull
		FROM pg_catalog.pg_attribute a
		JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'janitor' AND c.relname = $1
		  AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY a.attnum
	`, tableName)
	if err != nil {
		return fmt.Errorf("inspect Janitor table %q columns: %w", tableName, err)
	}
	defer rows.Close()
	var actual []janitorColumnSpec
	for rows.Next() {
		var column janitorColumnSpec
		if err := rows.Scan(&column.name, &column.typeName, &column.notNull); err != nil {
			return fmt.Errorf("scan Janitor table %q columns: %w", tableName, err)
		}
		actual = append(actual, column)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate Janitor table %q columns: %w", tableName, err)
	}
	if len(actual) != len(expected) {
		return fmt.Errorf("Janitor table %q has an unexpected column shape; manual reset required", tableName)
	}
	for i := range expected {
		if actual[i] != expected[i] {
			return fmt.Errorf("Janitor table %q has an unexpected column shape; manual reset required", tableName)
		}
	}
	return nil
}

func validateJanitorPrimaryKey(ctx context.Context, conn janitorQueryer, tableName, expected string) error {
	var primaryKeyCount int
	if err := conn.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_catalog.pg_constraint c
		JOIN pg_catalog.pg_class r ON r.oid = c.conrelid
		JOIN pg_catalog.pg_namespace n ON n.oid = r.relnamespace
		WHERE n.nspname = 'janitor' AND r.relname = $1 AND c.contype = 'p'
	`, tableName).Scan(&primaryKeyCount); err != nil {
		return fmt.Errorf("inspect Janitor table %q primary key: %w", tableName, err)
	}
	var primaryKey string
	if err := conn.QueryRow(ctx, `
		SELECT COALESCE(string_agg(a.attname, ',' ORDER BY key.ordinality), '')
		FROM pg_catalog.pg_constraint c
		JOIN pg_catalog.pg_class r ON r.oid = c.conrelid
		JOIN pg_catalog.pg_namespace n ON n.oid = r.relnamespace
		CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS key(attnum, ordinality)
		JOIN pg_catalog.pg_attribute a ON a.attrelid = r.oid AND a.attnum = key.attnum
		WHERE n.nspname = 'janitor' AND r.relname = $1 AND c.contype = 'p'
	`, tableName).Scan(&primaryKey); err != nil {
		return fmt.Errorf("read Janitor table %q primary key: %w", tableName, err)
	}
	if primaryKeyCount != 1 || primaryKey != expected {
		return fmt.Errorf("Janitor table %q has an unexpected primary key; manual reset required", tableName)
	}
	return nil
}

func normalizeCatalogDefinition(definition string) string {
	var normalized strings.Builder
	inSingleQuote, inDoubleQuote := false, false
	for _, r := range definition {
		if r == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
			normalized.WriteRune(r)
			continue
		}
		if r == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			normalized.WriteRune(r)
			continue
		}
		if inSingleQuote || inDoubleQuote {
			normalized.WriteRune(r)
			continue
		}
		if !unicode.IsSpace(r) {
			r = unicode.ToLower(r)
			normalized.WriteRune(r)
		}
	}
	return normalized.String()
}

type janitorCheckConstraint struct {
	columns    []string
	definition string
	validated  bool
	deferrable bool
	deferred   bool
}

func validateJanitorCheckConstraints(ctx context.Context, conn janitorQueryer, tableName string, expected []janitorCheckSpec) error {
	rows, err := conn.Query(ctx, `
		SELECT pg_catalog.pg_get_constraintdef(c.oid),
			c.convalidated,
			c.condeferrable,
			c.condeferred,
			COALESCE((
				SELECT array_agg(a.attname::text ORDER BY key.ordinality)
				FROM pg_catalog.unnest(c.conkey) WITH ORDINALITY AS key(attnum, ordinality)
				JOIN pg_catalog.pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = key.attnum
			), ARRAY[]::text[])
		FROM pg_catalog.pg_constraint c
		JOIN pg_catalog.pg_class r ON r.oid = c.conrelid
		JOIN pg_catalog.pg_namespace n ON n.oid = r.relnamespace
		WHERE n.nspname = 'janitor' AND r.relname = $1 AND c.contype = 'c'
	`, tableName)
	if err != nil {
		return fmt.Errorf("inspect Janitor table %q check constraints: %w", tableName, err)
	}
	defer rows.Close()
	var checks []janitorCheckConstraint
	for rows.Next() {
		var definition string
		var constraint janitorCheckConstraint
		if err := rows.Scan(&definition, &constraint.validated, &constraint.deferrable, &constraint.deferred, &constraint.columns); err != nil {
			return fmt.Errorf("scan Janitor table %q check constraints: %w", tableName, err)
		}
		constraint.definition = normalizeCatalogDefinition(definition)
		checks = append(checks, constraint)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate Janitor table %q check constraints: %w", tableName, err)
	}
	if len(checks) != len(expected) {
		return fmt.Errorf("Janitor table %q has an unexpected check constraint; manual reset required", tableName)
	}
	used := make([]bool, len(checks))
	for _, want := range expected {
		found := false
		for i, got := range checks {
			if used[i] || !janitorCheckMatches(got, want) {
				continue
			}
			used[i] = true
			found = true
			break
		}
		if !found {
			return fmt.Errorf("Janitor table %q has an unexpected check constraint; manual reset required", tableName)
		}
	}
	return nil
}

type janitorIndex struct {
	name         string
	table        string
	unique       bool
	primary      bool
	valid        bool
	live         bool
	keyColumns   int
	totalColumns int
	columns      []string
	predicate    string
}

func validateJanitorIndexes(ctx context.Context, conn janitorQueryer, relations map[string]janitorRelation, requireAll bool) error {
	rows, err := conn.Query(ctx, `
		SELECT index_rel.relname,
			table_rel.relname,
			i.indisunique,
			i.indisprimary,
			i.indisvalid,
			i.indislive,
			i.indnkeyatts,
			i.indnatts,
			COALESCE(ARRAY(
				SELECT COALESCE(a.attname::text, '')
				FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY AS key(attnum, ordinality)
				LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = key.attnum
				WHERE key.ordinality <= i.indnkeyatts
				ORDER BY key.ordinality
			), ARRAY[]::text[]),
			COALESCE(pg_catalog.pg_get_expr(i.indpred, i.indrelid), '')
		FROM pg_catalog.pg_class index_rel
		JOIN pg_catalog.pg_namespace index_ns ON index_ns.oid = index_rel.relnamespace
		JOIN pg_catalog.pg_index i ON i.indexrelid = index_rel.oid
		JOIN pg_catalog.pg_class table_rel ON table_rel.oid = i.indrelid
		WHERE index_ns.nspname = 'janitor' AND index_rel.relkind IN ('i', 'I')
		ORDER BY index_rel.relname
	`)
	if err != nil {
		return fmt.Errorf("inspect Janitor indexes: %w", err)
	}
	defer rows.Close()
	var actual []janitorIndex
	for rows.Next() {
		var index janitorIndex
		if err := rows.Scan(&index.name, &index.table, &index.unique, &index.primary, &index.valid, &index.live, &index.keyColumns, &index.totalColumns, &index.columns, &index.predicate); err != nil {
			return fmt.Errorf("scan Janitor indexes: %w", err)
		}
		actual = append(actual, index)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate Janitor indexes: %w", err)
	}
	expectedIndexes := make([]janitorIndexSpec, 0, len(janitorIndexSpecs))
	for _, expected := range janitorIndexSpecs {
		if requireAll {
			expectedIndexes = append(expectedIndexes, expected)
			continue
		}
		if _, exists := relations[expected.table]; exists {
			expectedIndexes = append(expectedIndexes, expected)
		}
	}
	if len(actual) != len(expectedIndexes) {
		return fmt.Errorf("Janitor schema has an unexpected index inventory; manual reset required")
	}
	for _, expected := range expectedIndexes {
		found := false
		for _, got := range actual {
			if got.name != expected.name {
				continue
			}
			found = true
			if !janitorIndexMatches(got, expected) {
				return fmt.Errorf("Janitor index %q has an unexpected shape; manual reset required", expected.name)
			}
			break
		}
		if !found {
			return fmt.Errorf("Janitor index %q is missing; manual reset required", expected.name)
		}
	}
	return nil
}

func sameJanitorStringSet(left, right []string) bool {
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	return reflect.DeepEqual(leftCopy, rightCopy)
}

func janitorCheckMatches(actual janitorCheckConstraint, expected janitorCheckSpec) bool {
	return actual.validated && !actual.deferrable && !actual.deferred &&
		sameJanitorStringSet(actual.columns, expected.columns) && actual.definition == expected.definition
}

func janitorIndexMatches(actual janitorIndex, expected janitorIndexSpec) bool {
	return actual.table == expected.table && actual.unique == expected.unique && actual.primary == expected.primary &&
		actual.valid == expected.valid && actual.live == expected.live && actual.keyColumns == len(expected.columns) &&
		actual.totalColumns == len(expected.columns) && reflect.DeepEqual(actual.columns, expected.columns) && actual.predicate == ""
}
