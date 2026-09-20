// Package db stores Janitor's maintenance state and its read-only view of Cashier entitlements.
package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const (
	maxDeploymentIdentityRows = 1
)

// LifecycleAction is the already-calculated action exposed by Cashier. Janitor
// never reconstructs subscription, team, quota, or grace state.
type LifecycleAction struct {
	MXID            string
	Revision        int64
	Action          string
	DueAt           time.Time
	DesiredUserType *string
}

type SubscriptionSnapshot struct {
	SubscriptionID    string
	Status            string
	ProviderProductID string
	TeamID            string
}

// ProviderSubscriptionSnapshot is the only billing state Janitor may read from
// Cashier. It is used for reporting discrepancies, never for entitlement writes.
func (s *Store) ProviderSubscriptionSnapshot(ctx context.Context) ([]SubscriptionSnapshot, error) {
	rows, err := s.pool.Query(ctx, `SELECT subscription_id, status, COALESCE(provider_product_id, ''), team_id::text FROM cashier.janitor_subscription_snapshot ORDER BY subscription_id COLLATE "C"`)
	if err != nil {
		return nil, fmt.Errorf("read Cashier subscription snapshot: %w", err)
	}
	defer rows.Close()
	var result []SubscriptionSnapshot
	for rows.Next() {
		var snapshot SubscriptionSnapshot
		if err := rows.Scan(&snapshot.SubscriptionID, &snapshot.Status, &snapshot.ProviderProductID, &snapshot.TeamID); err != nil {
			return nil, fmt.Errorf("scan Cashier subscription snapshot: %w", err)
		}
		if snapshot.SubscriptionID == "" || snapshot.Status == "" {
			return nil, fmt.Errorf("Cashier subscription snapshot contains an invalid row")
		}
		result = append(result, snapshot)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Cashier subscription snapshot: %w", err)
	}
	return result, nil
}

// ValidateServerName accepts the deployment hostname used to derive public endpoints and to bind
// append-only Janitor audit records. The Cashier deployment-identity view remains the authority
// for which deployment is connected to a database.
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

// ValidateDeploymentProfile is the one profile check shared by Plan, Janitor, and audit writes.
// Billing mode is explicit and never inferred from credentials or a hostname alone.
func ValidateDeploymentProfile(serverName, billingEnvironment string) error {
	if err := ValidateServerName(serverName); err != nil {
		return err
	}
	switch {
	case billingEnvironment == "test" || billingEnvironment == "live":
		return nil
	default:
		return fmt.Errorf("invalid SERVER_NAME/BILLING_ENVIRONMENT profile")
	}
}

// VerifyDeploymentIdentity re-reads Cashier's owner-rights identity view. Janitor deliberately
// has no access to Cashier base tables, including deployment_identity.
func (s *Store) VerifyDeploymentIdentity(ctx context.Context, serverName, billingEnvironment string) error {
	if err := ValidateDeploymentProfile(serverName, billingEnvironment); err != nil {
		return err
	}
	rows, err := s.pool.Query(ctx, `SELECT server_name, billing_environment FROM cashier.janitor_deployment_identity LIMIT $1`, maxDeploymentIdentityRows+1)
	if err != nil {
		return fmt.Errorf("read private Cashier deployment identity: %w", err)
	}
	defer rows.Close()
	var rowCount int
	var boundServerName, boundBillingEnvironment string
	for rows.Next() {
		rowCount++
		if err := rows.Scan(&boundServerName, &boundBillingEnvironment); err != nil {
			return fmt.Errorf("scan private Cashier deployment identity: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate private Cashier deployment identity: %w", err)
	}
	if rowCount == 0 {
		return fmt.Errorf("private Cashier has not bound the deployment identity")
	}
	if rowCount != 1 {
		return fmt.Errorf("Cashier deployment identity view must contain exactly one row")
	}
	if boundServerName != serverName || boundBillingEnvironment != billingEnvironment {
		return fmt.Errorf("Cashier deployment identity is bound to server %q and billing environment %q, not %q and %q", boundServerName, boundBillingEnvironment, serverName, billingEnvironment)
	}
	return nil
}

type lifecycleSuspensionResult struct {
	DueAt           time.Time
	DesiredUserType string
}

// SyncLifecycleAccount lets Cashier initialize the authoritative 48-hour clock
// from MAS without giving Janitor access to Cashier tables.
func (s *Store) SyncLifecycleAccount(ctx context.Context, mxid string, createdAt time.Time) error {
	if mxid == "" || createdAt.IsZero() {
		return fmt.Errorf("invalid lifecycle account")
	}
	if _, err := s.pool.Exec(ctx, `SELECT cashier.janitor_sync_account($1, $2)`, mxid, createdAt); err != nil {
		return fmt.Errorf("sync Cashier lifecycle account: %w", err)
	}
	return nil
}

func (s *Store) LifecycleActions(ctx context.Context) ([]LifecycleAction, error) {
	rows, err := s.pool.Query(ctx, `SELECT mxid, revision, action, due_at, desired_user_type FROM cashier.janitor_lifecycle_actions ORDER BY due_at, mxid COLLATE "C"`)
	if err != nil {
		return nil, fmt.Errorf("query Cashier lifecycle actions: %w", err)
	}
	defer rows.Close()
	var actions []LifecycleAction
	for rows.Next() {
		var action LifecycleAction
		if err := rows.Scan(&action.MXID, &action.Revision, &action.Action, &action.DueAt, &action.DesiredUserType); err != nil {
			return nil, fmt.Errorf("scan Cashier lifecycle action: %w", err)
		}
		if action.MXID == "" || (action.Action != "suspend" && action.Action != "start_removal" && action.Action != "finish_removal") {
			return nil, fmt.Errorf("Cashier lifecycle view returned an invalid action")
		}
		actions = append(actions, action)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Cashier lifecycle actions: %w", err)
	}
	return actions, nil
}

// ExecuteSuspension holds Cashier's account lock while Janitor performs the
// two native Synapse changes. A paid recovery therefore either commits before
// this transition or waits and immediately reverses it; it cannot be lost.
func (s *Store) ExecuteSuspension(ctx context.Context, mxid string, revision int64, apply func(context.Context, string) error) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin lifecycle suspension: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var claim lifecycleSuspensionResult
	if err := tx.QueryRow(ctx, `SELECT due_at, desired_user_type FROM cashier.janitor_claim_suspension($1, $2)`, mxid, revision).Scan(&claim.DueAt, &claim.DesiredUserType); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("claim lifecycle suspension: %w", err)
	}
	if claim.DesiredUserType != "wild" {
		return false, fmt.Errorf("Cashier returned unsupported suspension state %q", claim.DesiredUserType)
	}
	if err := apply(ctx, claim.DesiredUserType); err != nil {
		return false, err
	}
	var nextRevision int64
	var suspendedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT revision, suspended_at FROM cashier.janitor_complete_suspension($1, $2)`, mxid, revision).Scan(&nextRevision, &suspendedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("complete lifecycle suspension: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit lifecycle suspension: %w", err)
	}
	_ = nextRevision
	_ = suspendedAt
	return true, nil
}

func (s *Store) StartRemoval(ctx context.Context, mxid string, revision int64) (bool, int64, error) {
	var nextRevision int64
	var startedAt time.Time
	err := s.pool.QueryRow(ctx, `SELECT revision, removal_started_at FROM cashier.janitor_start_removal($1, $2)`, mxid, revision).Scan(&nextRevision, &startedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, fmt.Errorf("start lifecycle removal: %w", err)
	}
	return true, nextRevision, nil
}

func (s *Store) FinishRemoval(ctx context.Context, mxid string, revision int64) (bool, error) {
	var nextRevision int64
	var removedAt time.Time
	err := s.pool.QueryRow(ctx, `SELECT revision, removed_at FROM cashier.janitor_finish_removal($1, $2)`, mxid, revision).Scan(&nextRevision, &removedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("finish lifecycle removal: %w", err)
	}
	_ = nextRevision
	_ = removedAt
	return true, nil
}

// RunEvent is the bounded, append-only Janitor audit record. It deliberately contains no
// account identifiers, email addresses, provider errors, tokens, or free-form text.
type RunEvent struct {
	EventID            uuid.UUID
	RunID              uuid.UUID
	EventKind          string
	Status             string
	Outcome            string
	Reason             string
	ServerName         string
	BillingEnvironment string
	Considered         int64
	Skipped            int64
	LockedOrWouldLock  int64
	Failures           int64
	NotificationStatus string
	Labels             []string
}

var allowedRunEventLabels = map[string]struct{}{
	"database": {}, "mas_users": {}, "mas_emails": {},
	"candidate_recheck": {}, "lock": {}, "lock_readback": {}, "notification": {},
	"audit_started": {}, "audit_finished": {}, "cancelled": {}, "lifecycle": {},
}

func validateRunEvent(event RunEvent) error {
	if event.EventID == uuid.Nil || event.RunID == uuid.Nil {
		return fmt.Errorf("Janitor audit event IDs must be nonzero UUIDs")
	}
	if err := ValidateDeploymentProfile(event.ServerName, event.BillingEnvironment); err != nil {
		return err
	}
	if event.Considered < 0 || event.Skipped < 0 || event.LockedOrWouldLock < 0 || event.Failures < 0 {
		return fmt.Errorf("Janitor audit aggregates must be nonnegative")
	}
	if event.NotificationStatus != "not_attempted" && event.NotificationStatus != "succeeded" && event.NotificationStatus != "failed" {
		return fmt.Errorf("invalid Janitor audit notification status")
	}
	if len(event.Labels) > 16 {
		return fmt.Errorf("Janitor audit labels exceed sixteen entries")
	}
	seen := make(map[string]struct{}, len(event.Labels))
	for _, label := range event.Labels {
		if _, ok := allowedRunEventLabels[label]; !ok {
			return fmt.Errorf("Janitor audit label is not allowlisted")
		}
		if _, duplicate := seen[label]; duplicate {
			return fmt.Errorf("Janitor audit labels must be unique")
		}
		seen[label] = struct{}{}
	}
	if event.EventKind == "started" {
		if event.Status != "started" || event.Outcome != "pending" || event.Reason != "pending" || event.NotificationStatus != "not_attempted" {
			return fmt.Errorf("invalid Janitor started audit state")
		}
		if event.Considered != 0 || event.Skipped != 0 || event.LockedOrWouldLock != 0 || event.Failures != 0 {
			return fmt.Errorf("started Janitor audit event must have zero aggregates")
		}
		return nil
	}
	if event.EventKind != "finished" {
		return fmt.Errorf("invalid Janitor audit event kind")
	}
	if event.Status == "succeeded" {
		if event.Outcome != "success" {
			return fmt.Errorf("invalid Janitor success audit outcome")
		}
		if event.Failures != 0 {
			return fmt.Errorf("successful Janitor audit event must have zero failures")
		}
		if event.Reason != "disabled" && event.Reason != "no_eligible_accounts" {
			return fmt.Errorf("invalid Janitor success audit reason")
		}
		if event.Reason == "no_eligible_accounts" && event.LockedOrWouldLock != 0 {
			return fmt.Errorf("no-eligible Janitor audit event has a lock count")
		}
		if event.Reason == "disabled" && (event.Outcome != "success" || event.LockedOrWouldLock == 0) {
			return fmt.Errorf("disabled Janitor audit event is inconsistent")
		}
	} else if event.Status != "failed" || event.Outcome != "operational_failure" {
		return fmt.Errorf("invalid Janitor finished audit state")
	} else {
		if event.Failures == 0 {
			return fmt.Errorf("failed Janitor audit event must have a failure count")
		}
		switch event.Reason {
		case "database", "mas", "notification", "audit", "cancelled", "lock", "lock_readback":
		default:
			return fmt.Errorf("invalid Janitor failure audit reason")
		}
	}
	return nil
}

func (s *Store) InsertRunEvent(ctx context.Context, event RunEvent) error {
	if err := validateRunEvent(event); err != nil {
		return err
	}
	labels := append([]string(nil), event.Labels...)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO janitor.run_events
		(event_id, run_id, event_kind, status, outcome, reason, server_name, billing_environment,
		 dry_run, considered, skipped, locked_or_would_lock, failures, notification_status, labels)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE, $9, $10, $11, $12, $13, $14)`,
		event.EventID, event.RunID, event.EventKind, event.Status, event.Outcome, event.Reason,
		event.ServerName, event.BillingEnvironment, event.Considered, event.Skipped,
		event.LockedOrWouldLock, event.Failures, event.NotificationStatus, labels)
	if err != nil {
		return fmt.Errorf("insert Janitor audit event: %w", err)
	}
	return nil
}

// DigestCursor identifies the last email-attachment event included in a successfully delivered
// digest. MAS's stable email-resource ID makes events sharing a timestamp unambiguous.
type DigestCursor struct {
	CreatedAt time.Time
	EmailID   string
}

// Valid reports whether the cursor can be ordered without ambiguity against canonical MAS email
// resource ULIDs.
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
		       AND current_cursor.email_id COLLATE pg_catalog."C"
		           < EXCLUDED.email_id COLLATE pg_catalog."C")
	`, cursor.CreatedAt, cursor.EmailID)
	if err != nil {
		return fmt.Errorf("upsert janitor_digest_cursor: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("janitor_digest_cursor refused a non-advancing cursor")
	}
	return nil
}
