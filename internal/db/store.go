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

// ValidateDeploymentProfile is the one exact profile table shared by Plan, Janitor, and
// deployment-time checks. Billing mode is explicit and never inferred from credentials or a
// hostname alone.
func ValidateDeploymentProfile(serverName, billingEnvironment string) error {
	switch {
	case serverName == "telecrypt.io" && (billingEnvironment == "test" || billingEnvironment == "live"):
		return nil
	case serverName == "stage.telecrypt.io" && billingEnvironment == "test":
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

// LockExclusions returns the authoritative paid-entitlement projection exposed by Cashier. The
// view has exactly one column; no Janitor code reconstructs subscription, team, or seat state.
func (s *Store) LockExclusions(ctx context.Context) (map[string]struct{}, error) {
	rows, err := s.pool.Query(ctx, `SELECT mxid FROM cashier.janitor_lock_exclusions`)
	if err != nil {
		return nil, fmt.Errorf("query Cashier lock-exclusion view: %w", err)
	}
	defer rows.Close()
	exclusions := make(map[string]struct{})
	for rows.Next() {
		var mxid string
		if err := rows.Scan(&mxid); err != nil {
			return nil, fmt.Errorf("scan Cashier lock-exclusion view: %w", err)
		}
		if mxid == "" || len(mxid) > 255 || strings.ContainsAny(mxid, " \t\r\n") {
			return nil, fmt.Errorf("Cashier lock-exclusion view returned an empty MXID")
		}
		if _, duplicate := exclusions[mxid]; duplicate {
			return nil, fmt.Errorf("Cashier lock-exclusion view returned a duplicate MXID")
		}
		exclusions[mxid] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Cashier lock-exclusion view: %w", err)
	}
	return exclusions, nil
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
	"database": {}, "entitlement_view": {}, "mas_users": {}, "mas_emails": {},
	"candidate_recheck": {}, "lock": {}, "lock_readback": {}, "notification": {},
	"audit_started": {}, "audit_finished": {}, "cancelled": {},
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
		case "database", "mas", "entitlement_view", "notification", "audit", "cancelled", "lock", "lock_readback":
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
