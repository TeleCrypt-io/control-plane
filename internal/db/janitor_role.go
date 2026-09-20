package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type janitorRoleAttributes struct {
	currentRole, sessionRole                                                   string
	canLogin, inherit, superuser, createRole, createDB, replication, bypassRLS bool
	membershipCount                                                            int64
}

func validateJanitorRoleAttributes(a janitorRoleAttributes) error {
	if a.currentRole == "" || a.currentRole != a.sessionRole {
		return fmt.Errorf("current_user must equal session_user")
	}
	if !a.canLogin {
		return fmt.Errorf("role must have LOGIN")
	}
	if a.inherit {
		return fmt.Errorf("role must have NOINHERIT")
	}
	if a.superuser {
		return fmt.Errorf("role must not have SUPERUSER")
	}
	if a.createRole {
		return fmt.Errorf("role must not have CREATEROLE")
	}
	if a.createDB {
		return fmt.Errorf("role must not have CREATEDB")
	}
	if a.replication {
		return fmt.Errorf("role must not have REPLICATION")
	}
	if a.bypassRLS {
		return fmt.Errorf("role must not have BYPASSRLS")
	}
	if a.membershipCount != 0 {
		return fmt.Errorf("role must have zero role memberships in either direction")
	}
	return nil
}

func ValidateJanitorRole(ctx context.Context, pool *pgxpool.Pool) error {
	var a janitorRoleAttributes
	err := pool.QueryRow(ctx, `SELECT current_user, session_user, r.rolcanlogin, r.rolinherit, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls, (SELECT count(*) FROM pg_auth_members m WHERE m.member = r.oid OR m.roleid = r.oid) FROM pg_roles r WHERE r.rolname = current_user`).Scan(&a.currentRole, &a.sessionRole, &a.canLogin, &a.inherit, &a.superuser, &a.createRole, &a.createDB, &a.replication, &a.bypassRLS, &a.membershipCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("connected Janitor role is not present in pg_roles")
	}
	if err != nil {
		return fmt.Errorf("inspect connected Janitor role: %w", err)
	}
	if err := validateJanitorRoleAttributes(a); err != nil {
		return fmt.Errorf("Janitor database role contract: %w", err)
	}
	return nil
}

// ValidateJanitorSchemaACL confirms that only the schema owner can access Janitor's private
// migration/state namespace. The owner necessarily retains CREATE for its one-shot migrations.
func ValidateJanitorSchemaACL(ctx context.Context, pool *pgxpool.Pool) error {
	var owner, current string
	if err := pool.QueryRow(ctx, `SELECT current_user`).Scan(&current); err != nil {
		return fmt.Errorf("read Janitor database role: %w", err)
	}
	if err := pool.QueryRow(ctx, `SELECT r.rolname FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner WHERE n.nspname = 'janitor'`).Scan(&owner); err != nil {
		return fmt.Errorf("inspect Janitor schema owner: %w", err)
	}
	if owner != current {
		return fmt.Errorf("Janitor schema is owned by %q, not current role %q", owner, current)
	}
	var usage, create bool
	if err := pool.QueryRow(ctx, `SELECT has_schema_privilege(current_user, 'janitor', 'USAGE'), has_schema_privilege(current_user, 'janitor', 'CREATE')`).Scan(&usage, &create); err != nil {
		return fmt.Errorf("inspect Janitor schema privileges: %w", err)
	}
	if !usage || !create {
		return fmt.Errorf("Janitor schema owner requires USAGE and CREATE")
	}
	var unexpected bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) acl WHERE n.nspname = 'janitor' AND acl.grantee <> n.nspowner)`).Scan(&unexpected); err != nil {
		return fmt.Errorf("inspect Janitor schema ACL: %w", err)
	}
	if unexpected {
		return fmt.Errorf("Janitor schema grants must be limited to its owner")
	}
	return validateJanitorRelationOwnershipAndACL(ctx, pool)
}

// ValidateJanitorDatabaseContract verifies Janitor's private tables and the narrow Cashier
// views/functions used for lifecycle execution. Cashier base tables are never granted to or
// queried by this role.
func ValidateJanitorDatabaseContract(ctx context.Context, pool *pgxpool.Pool) error {
	var cashierOwner string
	if err := pool.QueryRow(ctx, `SELECT r.rolname FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner WHERE n.nspname = 'cashier'`).Scan(&cashierOwner); err != nil {
		return fmt.Errorf("inspect Cashier schema owner: %w", err)
	}
	var problem string
	err := pool.QueryRow(ctx, `SELECT COALESCE(CASE
	 WHEN to_regclass('janitor.schema_migrations') IS NULL THEN 'schema_migrations is missing'
	 WHEN to_regclass('janitor.janitor_digest_cursor') IS NULL THEN 'janitor_digest_cursor is missing'
	 WHEN to_regclass('janitor.run_events') IS NULL THEN 'run_events is missing'
	 WHEN EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname='janitor' AND c.relname IN ('schema_migrations','janitor_digest_cursor','run_events') AND c.relkind <> 'r') THEN 'Janitor state relation has wrong kind'
	 WHEN EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='janitor' AND c.relname IN ('schema_migrations','janitor_digest_cursor','run_events') AND r.rolname <> current_user) THEN 'Janitor state relation has wrong owner'
	 WHEN NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='cashier' AND c.relname='janitor_deployment_identity' AND c.relkind='v' AND r.rolname=$1) THEN 'janitor_deployment_identity view is missing or has wrong owner'
	 WHEN NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='cashier' AND c.relname='janitor_lifecycle_actions' AND c.relkind='v' AND r.rolname=$1) THEN 'janitor_lifecycle_actions view is missing or has wrong owner'
	 WHEN NOT has_table_privilege(current_user, 'cashier.janitor_deployment_identity', 'SELECT') THEN 'janitor_deployment_identity is not readable'
	 WHEN NOT has_table_privilege(current_user, 'cashier.janitor_lifecycle_actions', 'SELECT') THEN 'janitor_lifecycle_actions is not readable'
	 WHEN NOT has_function_privilege(current_user, 'cashier.janitor_sync_account(text,timestamptz)', 'EXECUTE') THEN 'janitor_sync_account is not executable'
	 WHEN NOT has_function_privilege(current_user, 'cashier.janitor_claim_suspension(text,bigint)', 'EXECUTE') THEN 'janitor_claim_suspension is not executable'
	 WHEN NOT has_function_privilege(current_user, 'cashier.janitor_complete_suspension(text,bigint)', 'EXECUTE') THEN 'janitor_complete_suspension is not executable'
	 WHEN NOT has_function_privilege(current_user, 'cashier.janitor_start_removal(text,bigint)', 'EXECUTE') THEN 'janitor_start_removal is not executable'
	 WHEN NOT has_function_privilege(current_user, 'cashier.janitor_finish_removal(text,bigint)', 'EXECUTE') THEN 'janitor_finish_removal is not executable'
	 ELSE NULL END, '')`, cashierOwner).Scan(&problem)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("validate Janitor database contract: %w", err)
	}
	if problem != "" {
		return fmt.Errorf("Janitor database contract: %s", problem)
	}
	if err := validateJanitorRelationOwnershipAndACL(ctx, pool); err != nil {
		return err
	}
	if err := validateJanitorCashierACL(ctx, pool, cashierOwner); err != nil {
		return err
	}
	return validateJanitorCashierViewColumns(ctx, pool)
}

func validateJanitorRelationOwnershipAndACL(ctx context.Context, pool *pgxpool.Pool) error {
	var problem string
	err := pool.QueryRow(ctx, `SELECT COALESCE(CASE
		 WHEN EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='janitor' AND c.relkind NOT IN ('i','I') AND r.rolname <> current_user) THEN 'Janitor relation has the wrong owner'
		 WHEN EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) acl WHERE n.nspname='janitor' AND c.relkind NOT IN ('i','I') AND c.relacl IS NOT NULL AND acl.grantee <> c.relowner) THEN 'Janitor relation has PUBLIC or other-role ACLs'
		 ELSE NULL END, '')`).Scan(&problem)
	if err != nil {
		return fmt.Errorf("inspect Janitor relation ownership and ACLs: %w", err)
	}
	if problem != "" {
		return fmt.Errorf("Janitor database contract: %s", problem)
	}
	return nil
}

func validateJanitorCashierACL(ctx context.Context, pool *pgxpool.Pool, expectedCashierOwner string) error {
	var problem string
	err := pool.QueryRow(ctx, `WITH role_ids AS (SELECT (SELECT oid FROM pg_roles WHERE rolname=current_user) janitor_oid, (SELECT oid FROM pg_roles WHERE rolname=$1) cashier_oid)
	 SELECT COALESCE(CASE
	 WHEN NOT EXISTS (SELECT 1 FROM role_ids WHERE cashier_oid IS NOT NULL) THEN 'expected Cashier role does not exist'
	 WHEN EXISTS (SELECT 1 FROM role_ids WHERE cashier_oid = janitor_oid) THEN 'Cashier owner must differ from Janitor role'
	 WHEN EXISTS (SELECT 1 FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname='cashier' AND r.rolname <> $1) THEN 'Cashier schema has the wrong owner'
	 WHEN EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='cashier' AND c.relkind NOT IN ('i','I') AND r.rolname <> $1) THEN 'Cashier relation has the wrong owner'
	 WHEN EXISTS (SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) acl CROSS JOIN role_ids WHERE n.nspname='cashier' AND acl.grantee NOT IN (role_ids.cashier_oid,role_ids.janitor_oid)) THEN 'Cashier schema has PUBLIC or other-role ACLs'
	 WHEN NOT has_schema_privilege(current_user,'cashier','USAGE') THEN 'Janitor cannot use Cashier schema'
	 WHEN has_schema_privilege(current_user,'cashier','CREATE') THEN 'Janitor has Cashier schema CREATE'
	 WHEN EXISTS (SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) acl CROSS JOIN role_ids WHERE n.nspname='cashier' AND role_ids.janitor_oid <> role_ids.cashier_oid AND acl.grantee=role_ids.janitor_oid AND (acl.privilege_type <> 'USAGE' OR acl.is_grantable)) THEN 'Cashier schema grants Janitor more than non-grantable USAGE'
	 WHEN EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl CROSS JOIN role_ids WHERE n.nspname='cashier' AND c.relkind NOT IN ('i','I') AND (acl.grantee NOT IN (c.relowner,role_ids.janitor_oid) OR (c.relname NOT IN ('janitor_deployment_identity','janitor_lifecycle_actions') AND acl.grantee=role_ids.janitor_oid) OR (c.relname IN ('janitor_deployment_identity','janitor_lifecycle_actions') AND acl.grantee=role_ids.janitor_oid AND (acl.privilege_type <> 'SELECT' OR acl.is_grantable)))) THEN 'Cashier relation has PUBLIC, other-role, or unexpected Janitor ACLs'
	 WHEN EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN role_ids ON TRUE WHERE n.nspname='cashier' AND p.proowner <> role_ids.cashier_oid) THEN 'Cashier routine has the wrong owner'
	 WHEN EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl CROSS JOIN role_ids WHERE n.nspname='cashier' AND (acl.grantee NOT IN (role_ids.cashier_oid,role_ids.janitor_oid) OR (acl.grantee = role_ids.janitor_oid AND (p.proname NOT IN ('janitor_sync_account','janitor_claim_suspension','janitor_complete_suspension','janitor_start_removal','janitor_finish_removal') OR acl.privilege_type <> 'EXECUTE' OR acl.is_grantable)))) THEN 'Cashier routine has PUBLIC or other-role ACLs'
	 WHEN EXISTS (SELECT 1 FROM pg_default_acl d JOIN pg_namespace n ON n.oid=d.defaclnamespace CROSS JOIN LATERAL aclexplode(d.defaclacl) acl CROSS JOIN role_ids WHERE n.nspname='cashier' AND (d.defaclrole <> role_ids.cashier_oid OR acl.grantee <> role_ids.cashier_oid)) THEN 'Cashier default privileges are not owner-only'
	 ELSE NULL END, '')`, expectedCashierOwner).Scan(&problem)
	if err != nil {
		return fmt.Errorf("inspect Cashier ownership and ACLs: %w", err)
	}
	if problem != "" {
		return fmt.Errorf("Janitor database contract: %s", problem)
	}
	return nil
}

func validateJanitorCashierViewColumns(ctx context.Context, pool *pgxpool.Pool) error {
	checks := []struct {
		name    string
		columns []string
	}{{"janitor_deployment_identity", []string{"server_name", "billing_environment"}}, {"janitor_lifecycle_actions", []string{"mxid", "revision", "action", "due_at", "desired_user_type"}}}
	for _, check := range checks {
		var options []string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(reloptions, ARRAY[]::text[]) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='cashier' AND c.relname=$1 AND c.relkind='v'`, check.name).Scan(&options); err != nil {
			return fmt.Errorf("inspect Cashier view %q options: %w", check.name, err)
		}
		barrier := false
		for _, option := range options {
			if option == "security_barrier=true" {
				barrier = true
			}
			if option == "security_invoker=true" {
				return fmt.Errorf("Cashier view %q must use owner rights", check.name)
			}
		}
		if !barrier {
			return fmt.Errorf("Cashier view %q must be security barrier", check.name)
		}
		rows, err := pool.Query(ctx, `SELECT a.attname FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='cashier' AND c.relname=$1 AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`, check.name)
		if err != nil {
			return fmt.Errorf("inspect Cashier view %q: %w", check.name, err)
		}
		var actual []string
		for rows.Next() {
			var column string
			if err := rows.Scan(&column); err != nil {
				rows.Close()
				return err
			}
			actual = append(actual, column)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(actual) != len(check.columns) {
			return fmt.Errorf("Cashier view %q has unexpected columns", check.name)
		}
		for i := range actual {
			if actual[i] != check.columns[i] {
				return fmt.Errorf("Cashier view %q has unexpected columns", check.name)
			}
		}
	}
	return nil
}
