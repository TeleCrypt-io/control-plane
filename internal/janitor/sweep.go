// Package janitor implements Janitor's one-shot maintenance process. Cashier owns entitlement;
// Janitor consumes only Cashier's two narrow views and the MAS admin API.
package janitor

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/db"
	"github.com/TeleCrypt-io/controlplane/internal/masadmin"
	"github.com/google/uuid"
)

const (
	lockAfter             = 48 * time.Hour
	cashierAdminLocalpart = "cashier-admin"
	auditCleanupTimeout   = 2 * time.Second
)

type Config struct {
	ServerName         string
	BillingEnvironment string
	OwnerEmail         string
}

type masAdminClient interface {
	ListUsers(context.Context) ([]masadmin.User, error)
	ListUserEmails(context.Context) ([]masadmin.UserEmail, error)
	GetUser(context.Context, string) (masadmin.User, error)
	HasUserEmail(context.Context, string) (bool, error)
	LockUser(context.Context, string) error
}

type store interface {
	VerifyDeploymentIdentity(context.Context, string, string) error
	LockExclusions(context.Context) (map[string]struct{}, error)
	JanitorDigestCursor(context.Context) (db.DigestCursor, bool, error)
	SetJanitorDigestCursor(context.Context, db.DigestCursor) error
	InsertRunEvent(context.Context, db.RunEvent) error
}

type Mailer interface {
	Send(context.Context, string, string, string) error
}

type Sweeper struct {
	mas    masAdminClient
	store  store
	mailer Mailer
	cfg    Config
}

func NewSweeper(mas masAdminClient, store store, mailer Mailer, cfg Config) *Sweeper {
	return &Sweeper{mas: mas, store: store, mailer: mailer, cfg: cfg}
}

type sweepState struct {
	runID         uuid.UUID
	considered    int64
	skipped       int64
	locked        int64
	failures      int64
	notification  string
	failureReason string
	labels        []string
	labelSet      map[string]struct{}
}

type operationError struct {
	reason string
	err    error
}

func (e *operationError) Error() string { return e.err.Error() }
func (e *operationError) Unwrap() error { return e.err }

func (s *sweepState) addLabel(label string) {
	if s.labelSet == nil {
		s.labelSet = make(map[string]struct{})
	}
	if _, exists := s.labelSet[label]; exists {
		return
	}
	s.labelSet[label] = struct{}{}
	s.labels = append(s.labels, label)
}

func (s *sweepState) fail(reason, label string) {
	s.failures++
	if s.failureReason == "" {
		s.failureReason = reason
	}
	if label != "" {
		s.addLabel(label)
	}
}

func (s *Sweeper) startedEvent(runID uuid.UUID) db.RunEvent {
	return db.RunEvent{
		EventID: uuid.New(), RunID: runID, EventKind: "started", Status: "started", Outcome: "pending", Reason: "pending",
		ServerName: s.cfg.ServerName, BillingEnvironment: s.cfg.BillingEnvironment,
		NotificationStatus: "not_attempted", Labels: []string{"audit_started"},
	}
}

func (s *Sweeper) finishedEvent(state *sweepState, status, outcome, reason string) db.RunEvent {
	labels := append([]string(nil), state.labels...)
	labels = append(labels, "audit_finished")
	seen := make(map[string]struct{}, len(labels))
	unique := labels[:0]
	for _, label := range labels {
		if _, exists := seen[label]; exists {
			continue
		}
		seen[label] = struct{}{}
		unique = append(unique, label)
	}
	return db.RunEvent{
		EventID: uuid.New(), RunID: state.runID, EventKind: "finished", Status: status, Outcome: outcome, Reason: reason,
		ServerName: s.cfg.ServerName, BillingEnvironment: s.cfg.BillingEnvironment,
		Considered: state.considered, Skipped: state.skipped, LockedOrWouldLock: state.locked,
		Failures: state.failures, NotificationStatus: state.notification, Labels: unique,
	}
}

// Sweep performs one complete run and always attempts the required finished event after a
// started event. Identity failure occurs before a run is authorized, so it intentionally emits no
// audit row. Failure to write either required row is itself a non-success result.
func (s *Sweeper) Sweep(ctx context.Context) error {
	if err := db.ValidateDeploymentProfile(s.cfg.ServerName, s.cfg.BillingEnvironment); err != nil {
		return err
	}
	if err := s.store.VerifyDeploymentIdentity(ctx, s.cfg.ServerName, s.cfg.BillingEnvironment); err != nil {
		return fmt.Errorf("janitor: deployment identity validation failed")
	}
	runID := uuid.New()
	state := &sweepState{runID: runID, notification: "not_attempted"}
	if err := s.store.InsertRunEvent(ctx, s.startedEvent(runID)); err != nil {
		return fmt.Errorf("janitor: started audit event failed")
	}

	finish := func(baseErr error) error {
		finishCtx, cancelFinish := boundedAuditContext(ctx)
		defer cancelFinish()
		if baseErr == nil && state.failures == 0 {
			reason := "no_eligible_accounts"
			if state.locked > 0 {
				reason = "disabled"
			}
			if err := s.store.InsertRunEvent(finishCtx, s.finishedEvent(state, "succeeded", "success", reason)); err != nil {
				return fmt.Errorf("janitor: finished audit event failed")
			}
			return nil
		}
		reason := state.failureReason
		if reason == "" {
			reason = "audit"
		}
		if err := s.store.InsertRunEvent(finishCtx, s.finishedEvent(state, "failed", "operational_failure", reason)); err != nil {
			if baseErr != nil {
				return fmt.Errorf("%v; janitor: finished audit event failed", baseErr)
			}
			return fmt.Errorf("janitor: finished audit event failed")
		}
		return baseErr
	}

	exclusions, err := s.store.LockExclusions(ctx)
	if err != nil {
		state.fail("entitlement_view", "entitlement_view")
		return finish(fmt.Errorf("janitor: entitlement view failed"))
	}
	state.addLabel("entitlement_view")
	users, err := s.mas.ListUsers(ctx)
	if err != nil {
		state.fail("mas", "mas_users")
		return finish(fmt.Errorf("janitor: list users failed"))
	}
	state.considered = int64(len(users))
	state.addLabel("mas_users")
	var emails []masadmin.UserEmail
	if s.cfg.OwnerEmail != "" {
		emails, err = s.mas.ListUserEmails(ctx)
		if err != nil {
			state.fail("mas", "mas_emails")
			return finish(fmt.Errorf("janitor: list user emails failed"))
		}
		state.addLabel("mas_emails")
	}
	if err := s.sweepLocks(ctx, users, exclusions, state); err != nil {
		return finish(err)
	}
	if ctx.Err() != nil {
		state.fail("cancelled", "cancelled")
		return finish(fmt.Errorf("janitor: sweep canceled"))
	}
	if err := s.sweepDigest(ctx, users, emails, state); err != nil {
		reason, label := "notification", "notification"
		var operation *operationError
		if errors.As(err, &operation) {
			reason = operation.reason
			label = failureLabel(operation.reason)
		}
		state.fail(reason, label)
		return finish(fmt.Errorf("janitor: digest failed"))
	}
	return finish(nil)
}

// boundedAuditContext keeps the required terminal event writable after cancellation while still
// bounding cleanup. An already-canceled parent would otherwise cancel its child immediately.
func boundedAuditContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil || parent.Err() != nil {
		return context.WithTimeout(context.Background(), auditCleanupTimeout)
	}
	return context.WithTimeout(parent, auditCleanupTimeout)
}

func failureLabel(reason string) string {
	switch reason {
	case "mas":
		return "mas_users"
	case "entitlement_view":
		return "entitlement_view"
	case "database", "notification", "audit", "cancelled", "lock", "lock_readback":
		return reason
	default:
		return "audit"
	}
}

func (s *Sweeper) mxid(username string) string {
	if !masadmin.ValidMXID(username, s.cfg.ServerName) {
		return ""
	}
	return fmt.Sprintf("@%s:%s", username, s.cfg.ServerName)
}

func (s *Sweeper) sweepLocks(ctx context.Context, users []masadmin.User, exclusions map[string]struct{}, state *sweepState) error {
	cutoff := time.Now().Add(-lockAfter)
	for _, snapshot := range users {
		if ctx.Err() != nil {
			state.fail("cancelled", "cancelled")
			return fmt.Errorf("janitor: sweep canceled")
		}
		mxid := s.mxid(snapshot.Username)
		if mxid == "" {
			state.skipped++
			state.fail("mas", "candidate_recheck")
			return fmt.Errorf("janitor: MAS candidate identity is invalid")
		}
		// This fixed MAS service identity is not a human or test account. Keep the
		// exclusion local and unconditional rather than manufacturing an email or
		// paid-entitlement projection for it.
		if snapshot.Username == cashierAdminLocalpart {
			state.skipped++
			continue
		}
		if snapshot.LockedAt != nil || snapshot.DeactivatedAt != nil || !snapshot.CreatedAt.Before(cutoff) {
			state.skipped++
			continue
		}
		if _, excluded := exclusions[mxid]; excluded {
			state.skipped++
			continue
		}
		state.addLabel("candidate_recheck")
		current, err := s.mas.GetUser(ctx, snapshot.ID)
		if err != nil {
			state.skipped++
			state.fail("mas", "candidate_recheck")
			return fmt.Errorf("janitor: candidate recheck failed")
		}
		currentMXID := s.mxid(current.Username)
		if current.ID != snapshot.ID || currentMXID == "" || currentMXID != mxid || current.CreatedAt.IsZero() || !current.CreatedAt.Equal(snapshot.CreatedAt) {
			state.skipped++
			state.fail("lock_readback", "candidate_recheck")
			return fmt.Errorf("janitor: candidate recheck returned inconsistent identity")
		}
		if current.LockedAt != nil || current.DeactivatedAt != nil || !current.CreatedAt.Before(cutoff) {
			state.skipped++
			continue
		}
		if _, excluded := exclusions[currentMXID]; excluded {
			state.skipped++
			continue
		}
		hasEmail, err := s.mas.HasUserEmail(ctx, current.ID)
		if err != nil {
			state.skipped++
			state.fail("mas", "candidate_recheck")
			return fmt.Errorf("janitor: candidate email recheck failed")
		}
		if hasEmail {
			state.skipped++
			continue
		}
		if err := s.mas.LockUser(ctx, current.ID); err != nil {
			state.fail("lock", "lock")
			return fmt.Errorf("janitor: account lock failed")
		}
		locked, err := s.mas.GetUser(ctx, current.ID)
		if err != nil || locked.ID != current.ID || locked.Username != current.Username || !locked.CreatedAt.Equal(current.CreatedAt) || locked.LockedAt == nil {
			state.fail("lock_readback", "lock_readback")
			return fmt.Errorf("janitor: account lock readback failed")
		}
		postEmail, err := s.mas.HasUserEmail(ctx, current.ID)
		if err != nil || postEmail {
			state.fail("lock_readback", "lock_readback")
			return fmt.Errorf("janitor: account lock email readback failed")
		}
		state.locked++
		state.addLabel("lock")
	}
	return nil
}

func (s *Sweeper) sweepDigest(ctx context.Context, users []masadmin.User, emails []masadmin.UserEmail, state *sweepState) error {
	if s.cfg.OwnerEmail == "" {
		return nil
	}
	cursor, found, err := s.store.JanitorDigestCursor(ctx)
	if err != nil {
		return &operationError{reason: "database", err: fmt.Errorf("digest cursor read failed")}
	}
	if !found {
		cursor = db.DigestCursor{CreatedAt: time.Unix(0, 0).UTC()}
	} else if !cursor.Valid() {
		return &operationError{reason: "database", err: fmt.Errorf("digest cursor is invalid")}
	}
	usersByID := make(map[string]masadmin.User, len(users))
	for _, user := range users {
		if !validEventID(user.ID) || user.Username == "" || user.CreatedAt.IsZero() {
			return &operationError{reason: "mas", err: fmt.Errorf("digest user snapshot is invalid")}
		}
		usersByID[user.ID] = user
	}
	after := func(at time.Time, id string) bool {
		return at.After(cursor.CreatedAt) || (at.Equal(cursor.CreatedAt) && id > cursor.EmailID)
	}
	before := func(a, b masadmin.UserEmail) bool {
		return a.CreatedAt.Before(b.CreatedAt) || (a.CreatedAt.Equal(b.CreatedAt) && a.ID < b.ID)
	}
	first := make(map[string]masadmin.UserEmail)
	var high masadmin.UserEmail
	for _, email := range emails {
		if !validEventID(email.ID) || !validEventID(email.UserID) || email.CreatedAt.IsZero() {
			return &operationError{reason: "mas", err: fmt.Errorf("digest email snapshot is invalid")}
		}
		if after(email.CreatedAt, email.ID) {
			if _, ok := usersByID[email.UserID]; !ok {
				return &operationError{reason: "mas", err: fmt.Errorf("digest snapshots disagree")}
			}
			if high.ID == "" || before(high, email) {
				high = email
			}
		}
		if old, ok := first[email.UserID]; !ok || before(email, old) {
			first[email.UserID] = email
		}
	}
	type candidate struct {
		mxid          string
		userCreatedAt time.Time
		email         masadmin.UserEmail
	}
	candidates := make([]candidate, 0)
	for userID, email := range first {
		if !after(email.CreatedAt, email.ID) {
			continue
		}
		user, ok := usersByID[userID]
		if !ok {
			return &operationError{reason: "mas", err: fmt.Errorf("digest snapshots disagree")}
		}
		mxid := s.mxid(user.Username)
		if mxid == "" {
			return &operationError{reason: "mas", err: fmt.Errorf("digest user identity is invalid")}
		}
		candidates = append(candidates, candidate{mxid: mxid, userCreatedAt: user.CreatedAt, email: email})
	}
	if len(candidates) == 0 {
		if high.ID != "" {
			if err := s.store.SetJanitorDigestCursor(ctx, db.DigestCursor{CreatedAt: high.CreatedAt, EmailID: high.ID}); err != nil {
				return &operationError{reason: "database", err: fmt.Errorf("digest cursor advance failed")}
			}
		}
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool { return before(candidates[i].email, candidates[j].email) })
	var body strings.Builder
	fmt.Fprintf(&body, "%d new human sign-up(s) awaiting review:\r\n\r\n", len(candidates))
	for _, candidate := range candidates {
		fmt.Fprintf(&body, "%s  created %s\r\n", candidate.mxid, candidate.userCreatedAt.Format(time.RFC3339))
	}
	if err := s.mailer.Send(ctx, s.cfg.OwnerEmail, fmt.Sprintf("TeleCrypt.io: %d new sign-up(s) awaiting review", len(candidates)), body.String()); err != nil {
		state.notification = "failed"
		return &operationError{reason: "notification", err: fmt.Errorf("notification delivery failed")}
	}
	state.notification = "succeeded"
	state.addLabel("notification")
	if high.ID != "" {
		if err := s.store.SetJanitorDigestCursor(ctx, db.DigestCursor{CreatedAt: high.CreatedAt, EmailID: high.ID}); err != nil {
			return &operationError{reason: "database", err: fmt.Errorf("digest cursor advance failed")}
		}
	}
	return nil
}

func validEventID(value string) bool {
	if len(value) != 26 || value[0] > '7' {
		return false
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for _, r := range value {
		if !strings.ContainsRune(alphabet, r) {
			return false
		}
	}
	return true
}
