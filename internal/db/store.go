// Package db stores Janitor's maintenance state and reads Cashier's ordinary tables.
package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

type SubscriptionSnapshot struct {
	SubscriptionID    string
	Status            string
	ProviderProductID string
	TeamID            string
}

// ProviderSubscriptionSnapshot reads Cashier's billing tables for reconciliation only. Janitor
// never writes provider, payment, or membership state as a result of this comparison.
func (s *Store) ProviderSubscriptionSnapshot(ctx context.Context) ([]SubscriptionSnapshot, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT binding.subscription_id, binding.status, COALESCE(team.provider_product_id, ''), binding.team_id::text
		FROM cashier.dodo_subscription_bindings AS binding
		JOIN cashier.teams AS team ON team.id = binding.team_id
		WHERE binding.is_current
		ORDER BY binding.subscription_id COLLATE "C"`)
	if err != nil {
		return nil, fmt.Errorf("read Cashier subscription bindings: %w", err)
	}
	defer rows.Close()
	var result []SubscriptionSnapshot
	for rows.Next() {
		var snapshot SubscriptionSnapshot
		if err := rows.Scan(&snapshot.SubscriptionID, &snapshot.Status, &snapshot.ProviderProductID, &snapshot.TeamID); err != nil {
			return nil, fmt.Errorf("scan Cashier subscription binding: %w", err)
		}
		if snapshot.SubscriptionID == "" || snapshot.Status == "" {
			return nil, fmt.Errorf("Cashier subscription binding contains an invalid row")
		}
		result = append(result, snapshot)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Cashier subscription bindings: %w", err)
	}
	return result, nil
}

// ValidateServerName accepts the hostname used to construct Matrix identities and public URLs.
func ValidateServerName(serverName string) error {
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

// ValidateDeploymentProfile validates the explicit billing mode. It is configuration validation;
// Janitor does not compare it with a second deployment-identity record in Cashier.
func ValidateDeploymentProfile(serverName, billingEnvironment string) error {
	if err := ValidateServerName(serverName); err != nil {
		return err
	}
	if billingEnvironment != "test" && billingEnvironment != "live" {
		return fmt.Errorf("invalid SERVER_NAME/BILLING_ENVIRONMENT profile")
	}
	return nil
}

// LifecycleAction is calculated from Cashier's account, team, and membership tables. A nightly
// Janitor run is the only lifecycle writer, so row locks are sufficient; no revision or function
// protocol is needed.
type LifecycleAction struct {
	MXID            string
	Action          string
	DueAt           time.Time
	DesiredUserType *string
}

// paidMembershipSQL is evaluated with an account_ledger row aliased as account. Fixed tiers use
// the same oldest-member ordering as Cashier's entitlement calculation.
const paidMembershipSQL = `
	EXISTS (
		SELECT 1
		FROM (
			SELECT s.mxid, s.team_id, t.member_limit,
				row_number() OVER (PARTITION BY s.team_id ORDER BY s.created_at ASC, s.mxid COLLATE "C" ASC) AS member_rank
			FROM cashier.seats AS s
			JOIN cashier.teams AS t ON t.id = s.team_id
			WHERE t.subscription_status IN ('active', 'past_due', 'on_hold')
			  AND t.tier_id BETWEEN 1 AND 4
		) AS paid
		WHERE paid.mxid = account.mxid
		  AND paid.member_rank <= paid.member_limit
	)`

// SyncLifecycleAccount records a MAS account if Cashier has not seen it yet and initializes the
// normal 48-hour free-account suspension deadline. Existing lifecycle decisions are preserved.
func (s *Store) SyncLifecycleAccount(ctx context.Context, mxid string, createdAt time.Time) error {
	if mxid == "" || createdAt.IsZero() {
		return fmt.Errorf("invalid lifecycle account")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO cashier.account_ledger (mxid, created_at, suspend_due_at)
		VALUES ($1, $2, $2 + interval '48 hours')
		ON CONFLICT (mxid) DO UPDATE
		SET created_at = LEAST(account_ledger.created_at, EXCLUDED.created_at),
		    suspend_due_at = CASE
				WHEN account_ledger.removed_at IS NULL
				 AND account_ledger.departure_at IS NULL
				 AND account_ledger.grace_tier_id IS NULL
				 AND account_ledger.suspended_at IS NULL
				 AND account_ledger.removal_started_at IS NULL
				THEN LEAST(COALESCE(account_ledger.suspend_due_at, EXCLUDED.suspend_due_at), EXCLUDED.suspend_due_at)
				ELSE account_ledger.suspend_due_at
			END,
		    updated_at = now()`, mxid, createdAt)
	if err != nil {
		return fmt.Errorf("sync Cashier lifecycle account: %w", err)
	}
	return nil
}

func (s *Store) LifecycleActions(ctx context.Context) ([]LifecycleAction, error) {
	query := `
		SELECT mxid, action, due_at, desired_user_type
		FROM (
			SELECT account.mxid, 'suspend'::text AS action, account.suspend_due_at AS due_at, 'wild'::text AS desired_user_type
			FROM cashier.account_ledger AS account
			WHERE account.removed_at IS NULL
			  AND account.suspend_due_at IS NOT NULL AND account.suspend_due_at <= now()
			  AND account.suspended_at IS NULL AND account.removal_started_at IS NULL
			  AND NOT ` + paidMembershipSQL + `
			  AND NOT EXISTS (
				SELECT 1 FROM cashier.account_ledger AS grace
				WHERE grace.mxid = account.mxid
				  AND grace.grace_tier_id BETWEEN 1 AND 4
				  AND grace.suspend_due_at > now()
			  )
			UNION ALL
			SELECT account.mxid, 'start_removal'::text AS action,
			       account.suspended_at + CASE WHEN account.departure_at IS NULL THEN interval '30 days' ELSE interval '90 days' END,
			       NULL::text
			FROM cashier.account_ledger AS account
			WHERE account.removed_at IS NULL AND account.suspended_at IS NOT NULL
			  AND account.suspended_at + CASE WHEN account.departure_at IS NULL THEN interval '30 days' ELSE interval '90 days' END <= now()
			  AND account.removal_started_at IS NULL
			  AND NOT ` + paidMembershipSQL + `
			UNION ALL
			SELECT account.mxid, 'finish_removal'::text AS action, account.removal_started_at, NULL::text
			FROM cashier.account_ledger AS account
			WHERE account.removed_at IS NULL AND account.removal_started_at IS NOT NULL
		) AS actions
		ORDER BY due_at, mxid COLLATE "C"`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query Cashier lifecycle tables: %w", err)
	}
	defer rows.Close()
	var actions []LifecycleAction
	for rows.Next() {
		var action LifecycleAction
		if err := rows.Scan(&action.MXID, &action.Action, &action.DueAt, &action.DesiredUserType); err != nil {
			return nil, fmt.Errorf("scan Cashier lifecycle row: %w", err)
		}
		actions = append(actions, action)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Cashier lifecycle rows: %w", err)
	}
	return actions, nil
}

// ExecuteSuspension locks one account row while the policy and Synapse callbacks run, then records
// the native suspension timestamp. The callbacks are idempotent and the nightly job is single-use.
func (s *Store) ExecuteSuspension(ctx context.Context, mxid string, apply func(context.Context, string) error) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin lifecycle suspension: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var dueAt time.Time
	query := `SELECT account.suspend_due_at FROM cashier.account_ledger AS account
		WHERE account.mxid = $1 AND account.removed_at IS NULL
		  AND account.suspend_due_at IS NOT NULL AND account.suspend_due_at <= now()
		  AND account.suspended_at IS NULL AND account.removal_started_at IS NULL
		  AND NOT ` + paidMembershipSQL + `
		FOR UPDATE`
	if err := tx.QueryRow(ctx, query, mxid).Scan(&dueAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("lock lifecycle suspension: %w", err)
	}
	if err := apply(ctx, "wild"); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE cashier.account_ledger SET suspended_at = now(), updated_at = now() WHERE mxid = $1`, mxid); err != nil {
		return false, fmt.Errorf("record lifecycle suspension: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit lifecycle suspension: %w", err)
	}
	return true, nil
}

func (s *Store) StartRemoval(ctx context.Context, mxid string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin lifecycle removal: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var started time.Time
	query := `SELECT account.suspended_at FROM cashier.account_ledger AS account
		WHERE account.mxid = $1 AND account.removed_at IS NULL AND account.suspended_at IS NOT NULL
		  AND account.suspended_at + CASE WHEN account.departure_at IS NULL THEN interval '30 days' ELSE interval '90 days' END <= now()
		  AND account.removal_started_at IS NULL AND NOT ` + paidMembershipSQL + `
		FOR UPDATE`
	if err := tx.QueryRow(ctx, query, mxid).Scan(&started); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("lock lifecycle removal: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE cashier.account_ledger SET removal_started_at = now(), updated_at = now() WHERE mxid = $1`, mxid); err != nil {
		return false, fmt.Errorf("record lifecycle removal start: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit lifecycle removal start: %w", err)
	}
	return true, nil
}

func (s *Store) FinishRemoval(ctx context.Context, mxid string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin lifecycle cleanup: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var started time.Time
	if err := tx.QueryRow(ctx, `SELECT removal_started_at FROM cashier.account_ledger WHERE mxid = $1 AND removed_at IS NULL AND removal_started_at IS NOT NULL FOR UPDATE`, mxid).Scan(&started); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("lock lifecycle cleanup: %w", err)
	}
	var paid bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cashier.seats AS s JOIN cashier.teams AS t ON t.id = s.team_id WHERE s.mxid = $1 AND t.subscription_status IN ('active', 'past_due', 'on_hold') AND t.tier_id BETWEEN 1 AND 4)`, mxid).Scan(&paid); err != nil {
		return false, fmt.Errorf("check paid membership before cleanup: %w", err)
	}
	if paid {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE cashier.account_ledger SET removed_at = now(), updated_at = now() WHERE mxid = $1`, mxid); err != nil {
		return false, fmt.Errorf("record lifecycle cleanup: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM cashier.seats WHERE mxid = $1`, mxid); err != nil {
		return false, fmt.Errorf("delete removed member: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM cashier.teams AS team WHERE team.admin_mxid = $1 AND NOT EXISTS (SELECT 1 FROM cashier.seats AS seat WHERE seat.team_id = team.id) AND NOT EXISTS (SELECT 1 FROM cashier.dodo_subscription_bindings AS binding WHERE binding.team_id = team.id)`, mxid); err != nil {
		return false, fmt.Errorf("delete empty team: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit lifecycle cleanup: %w", err)
	}
	return true, nil
}

// DigestCursor identifies the last email-attachment event included in a successfully delivered
// digest. MAS's stable email-resource ID makes events sharing a timestamp unambiguous.
type DigestCursor struct {
	CreatedAt time.Time
	EmailID   string
}

func (c DigestCursor) Valid() bool {
	if c.CreatedAt.IsZero() || len(c.EmailID) != 26 || c.EmailID[0] > '7' {
		return false
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for _, r := range c.EmailID {
		if !strings.ContainsRune(alphabet, r) {
			return false
		}
	}
	return true
}

func (s *Store) JanitorDigestCursor(ctx context.Context) (DigestCursor, bool, error) {
	var cursor DigestCursor
	err := s.pool.QueryRow(ctx, `SELECT created_at, email_id FROM janitor.janitor_digest_cursor WHERE singleton = TRUE`).Scan(&cursor.CreatedAt, &cursor.EmailID)
	if errors.Is(err, pgx.ErrNoRows) {
		return DigestCursor{}, false, nil
	}
	if err != nil {
		return DigestCursor{}, false, fmt.Errorf("query janitor_digest_cursor: %w", err)
	}
	return cursor, true, nil
}

func (s *Store) SetJanitorDigestCursor(ctx context.Context, cursor DigestCursor) error {
	if !cursor.Valid() {
		return fmt.Errorf("janitor_digest_cursor is invalid")
	}
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO janitor.janitor_digest_cursor AS current_cursor (singleton, created_at, email_id)
		VALUES (TRUE, $1, $2)
		ON CONFLICT (singleton) DO UPDATE
		SET created_at = EXCLUDED.created_at, email_id = EXCLUDED.email_id
		WHERE current_cursor.created_at < EXCLUDED.created_at
		   OR (current_cursor.created_at = EXCLUDED.created_at
		       AND current_cursor.email_id COLLATE pg_catalog."C" < EXCLUDED.email_id COLLATE pg_catalog."C")
	`, cursor.CreatedAt, cursor.EmailID)
	if err != nil {
		return fmt.Errorf("upsert janitor_digest_cursor: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("janitor_digest_cursor refused a non-advancing cursor")
	}
	return nil
}
