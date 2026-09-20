// Package janitor implements one scheduled lifecycle-maintenance run. It has no HTTP server.
// Cashier owns entitlement and lifecycle state; Janitor executes only the time-due actions
// exposed through its narrow database view/functions.
package janitor

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/db"
	"github.com/TeleCrypt-io/controlplane/internal/httpdiag"
	"github.com/TeleCrypt-io/controlplane/internal/masadmin"
	"github.com/google/uuid"
)

const auditCleanupTimeout = 2 * time.Second

type Config struct {
	ServerName         string
	BillingEnvironment string
	OwnerEmail         string
}

type masAdminClient interface {
	ListUsers(context.Context) ([]masadmin.User, error)
	ListUserEmails(context.Context) ([]masadmin.UserEmail, error)
}

type synapseAdminClient interface {
	SuspendUser(context.Context, string, bool) error
}

type synapsePolicyClient interface {
	SetUserType(context.Context, string, string) error
	ReadUserType(context.Context, string) (*string, error)
}

type masRemovalClient interface {
	DeactivateUser(context.Context, string) error
}

type mediaRemovalClient interface {
	DeleteAllMedia(context.Context, string) error
}

type lifecycleStore interface {
	SyncLifecycleAccount(context.Context, string, time.Time) error
	LifecycleActions(context.Context) ([]db.LifecycleAction, error)
	ExecuteSuspension(context.Context, string, int64, func(context.Context, string) error) (bool, error)
	StartRemoval(context.Context, string, int64) (bool, int64, error)
	FinishRemoval(context.Context, string, int64) (bool, error)
}

// Discrepancy is intentionally provider-neutral. Janitor reports it to the owner and does not
// mutate Cashier, subscriptions, memberships, or files as a consequence.
type Discrepancy struct {
	TeamID       string
	Subscription string
	Kind         string
	Detail       string
}

// DodoReconciler performs one bounded read-only provider snapshot. Implementations must use a
// read-only API key and must not expose a provider loop or a write operation.
type DodoReconciler interface {
	Reconcile(context.Context) ([]Discrepancy, error)
}

type store interface {
	VerifyDeploymentIdentity(context.Context, string, string) error
	lifecycleStore
	JanitorDigestCursor(context.Context) (db.DigestCursor, bool, error)
	SetJanitorDigestCursor(context.Context, db.DigestCursor) error
	InsertRunEvent(context.Context, db.RunEvent) error
}

type Mailer interface {
	Send(context.Context, string, string, string) error
}

type Sweeper struct {
	mas     masAdminClient
	synapse synapseAdminClient
	store   store
	mailer  Mailer
	dodo    DodoReconciler
	cfg     Config
}

func NewLifecycleSweeper(mas masAdminClient, synapse synapseAdminClient, store store, mailer Mailer, dodo DodoReconciler, cfg Config) *Sweeper {
	return &Sweeper{mas: mas, synapse: synapse, store: store, mailer: mailer, dodo: dodo, cfg: cfg}
}

type sweepState struct {
	runID         uuid.UUID
	considered    int64
	skipped       int64
	locked        int64 // historical audit column; counts native suspensions for compatibility
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
	return db.RunEvent{
		EventID: uuid.New(), RunID: state.runID, EventKind: "finished", Status: status, Outcome: outcome, Reason: reason,
		ServerName: s.cfg.ServerName, BillingEnvironment: s.cfg.BillingEnvironment,
		Considered: state.considered, Skipped: state.skipped, LockedOrWouldLock: state.locked,
		Failures: state.failures, NotificationStatus: state.notification, Labels: labels,
	}
}

// Sweep performs exactly one complete run. It has no provider retry loop and always attempts the
// terminal audit row after a run has been authorized and its started row has been written.
func (s *Sweeper) Sweep(ctx context.Context) error {
	if err := db.ValidateDeploymentProfile(s.cfg.ServerName, s.cfg.BillingEnvironment); err != nil {
		return err
	}
	if err := s.store.VerifyDeploymentIdentity(ctx, s.cfg.ServerName, s.cfg.BillingEnvironment); err != nil {
		return httpdiag.WrapCause("janitor: deployment identity validation failed", err)
	}
	runID := uuid.New()
	state := &sweepState{runID: runID, notification: "not_attempted"}
	if err := s.store.InsertRunEvent(ctx, s.startedEvent(runID)); err != nil {
		return httpdiag.WrapCause("janitor: started audit event failed", err)
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
				return httpdiag.WrapCause("janitor: finished audit event failed", err)
			}
			return nil
		}
		reason := state.failureReason
		if reason == "" {
			reason = "audit"
		}
		if err := s.store.InsertRunEvent(finishCtx, s.finishedEvent(state, "failed", "operational_failure", reason)); err != nil {
			return errors.Join(baseErr, httpdiag.WrapCause("janitor: finished audit event failed", err))
		}
		return baseErr
	}

	users, err := s.mas.ListUsers(ctx)
	if err != nil {
		state.fail("mas", "mas_users")
		return finish(httpdiag.WrapCause("janitor: list users failed", err))
	}
	state.considered = int64(len(users))
	state.addLabel("mas_users")
	if err := s.sweepAuthoritativeLifecycle(ctx, users, s.store, state); err != nil {
		return finish(err)
	}
	if ctx.Err() != nil {
		state.fail("cancelled", "cancelled")
		return finish(httpdiag.WrapCause("janitor: sweep canceled", ctx.Err()))
	}
	if err := s.sweepProvider(ctx, state); err != nil {
		return finish(err)
	}
	var emails []masadmin.UserEmail
	if s.cfg.OwnerEmail != "" {
		emails, err = s.mas.ListUserEmails(ctx)
		if err != nil {
			state.fail("mas", "mas_emails")
			return finish(httpdiag.WrapCause("janitor: list user emails failed", err))
		}
		state.addLabel("mas_emails")
	}
	if err := s.sweepDigest(ctx, users, emails, state); err != nil {
		reason, label := "notification", "notification"
		var operation *operationError
		if errors.As(err, &operation) {
			reason = operation.reason
			label = failureLabel(operation.reason)
		}
		state.fail(reason, label)
		return finish(httpdiag.WrapCause("janitor: digest failed", err))
	}
	return finish(nil)
}

func (s *Sweeper) sweepAuthoritativeLifecycle(ctx context.Context, users []masadmin.User, lifecycle lifecycleStore, state *sweepState) error {
	for _, snapshot := range users {
		mxid := s.mxid(snapshot.Username)
		if mxid == "" || snapshot.DeactivatedAt != nil {
			continue
		}
		if err := lifecycle.SyncLifecycleAccount(ctx, mxid, snapshot.CreatedAt); err != nil {
			state.fail("database", "database")
			return httpdiag.WrapCause("janitor: synchronize lifecycle account", err)
		}
	}
	actions, err := lifecycle.LifecycleActions(ctx)
	if err != nil {
		state.fail("database", "database")
		return httpdiag.WrapCause("janitor: read lifecycle actions", err)
	}
	state.addLabel("lifecycle")
	usersByUsername := make(map[string]masadmin.User, len(users))
	for _, user := range users {
		usersByUsername[user.Username] = user
	}
	for _, action := range actions {
		if ctx.Err() != nil {
			state.fail("cancelled", "cancelled")
			return httpdiag.WrapCause("janitor: lifecycle sweep canceled", ctx.Err())
		}
		switch action.Action {
		case "suspend":
			if action.DesiredUserType == nil || *action.DesiredUserType != "wild" {
				state.fail("database", "database")
				return fmt.Errorf("janitor: Cashier returned an unsupported lifecycle projection")
			}
			applied, err := lifecycle.ExecuteSuspension(ctx, action.MXID, action.Revision, func(callCtx context.Context, desired string) error {
				policy, ok := s.synapse.(synapsePolicyClient)
				if !ok {
					return errors.New("synapse admin client does not support user_type projection")
				}
				if err := policy.SetUserType(callCtx, action.MXID, desired); err != nil {
					return err
				}
				got, err := policy.ReadUserType(callCtx, action.MXID)
				if err != nil || got == nil || *got != desired {
					if err == nil {
						err = fmt.Errorf("user_type projection readback mismatch")
					}
					return err
				}
				return s.synapse.SuspendUser(callCtx, action.MXID, true)
			})
			if err != nil {
				state.fail("lock", "lock")
				return httpdiag.WrapCause("janitor: suspend lifecycle account", err)
			}
			if applied {
				state.locked++
				state.addLabel("lock")
			}
		case "start_removal":
			started, nextRevision, err := lifecycle.StartRemoval(ctx, action.MXID, action.Revision)
			if err != nil {
				state.fail("database", "database")
				return httpdiag.WrapCause("janitor: start lifecycle removal", err)
			}
			if started {
				if err := s.finishExternalRemoval(ctx, action.MXID, usersByUsername); err != nil {
					state.fail("mas", "mas_users")
					return err
				}
				if _, err := lifecycle.FinishRemoval(ctx, action.MXID, nextRevision); err != nil {
					state.fail("database", "database")
					return httpdiag.WrapCause("janitor: finish lifecycle removal", err)
				}
			}
		case "finish_removal":
			if err := s.finishExternalRemoval(ctx, action.MXID, usersByUsername); err != nil {
				state.fail("mas", "mas_users")
				return err
			}
			if _, err := lifecycle.FinishRemoval(ctx, action.MXID, action.Revision); err != nil {
				state.fail("database", "database")
				return httpdiag.WrapCause("janitor: finish lifecycle removal", err)
			}
		}
	}
	return nil
}

func (s *Sweeper) finishExternalRemoval(ctx context.Context, mxid string, users map[string]masadmin.User) error {
	if media, ok := s.synapse.(mediaRemovalClient); ok {
		if err := media.DeleteAllMedia(ctx, mxid); err != nil {
			return httpdiag.WrapCause("janitor: delete account media", err)
		}
	}
	remover, ok := s.mas.(masRemovalClient)
	if !ok {
		return errors.New("MAS client does not support account deactivation")
	}
	localpart := strings.TrimPrefix(mxid, "@")
	parts := strings.SplitN(localpart, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("janitor: invalid lifecycle MXID %q", mxid)
	}
	user, ok := users[parts[0]]
	if !ok {
		return fmt.Errorf("janitor: MAS user for lifecycle MXID %q is unavailable", mxid)
	}
	if user.DeactivatedAt == nil {
		if err := remover.DeactivateUser(ctx, user.ID); err != nil {
			return httpdiag.WrapCause("janitor: deactivate MAS account", err)
		}
	}
	return nil
}

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

func (s *Sweeper) sweepProvider(ctx context.Context, state *sweepState) error {
	if s.dodo == nil {
		return nil
	}
	discrepancies, err := s.dodo.Reconcile(ctx)
	if err != nil {
		state.notification = "failed"
		return &operationError{reason: "notification", err: httpdiag.WrapCause("provider reconciliation failed", err)}
	}
	if len(discrepancies) == 0 || s.cfg.OwnerEmail == "" {
		return nil
	}
	rows := make([]string, 0, len(discrepancies))
	for _, discrepancy := range discrepancies {
		rows = append(rows, fmt.Sprintf("%s %s %s", discrepancy.TeamID, discrepancy.Subscription, discrepancy.Kind))
	}
	sort.Strings(rows)
	body := "Dodo reconciliation found discrepancies; no automatic correction was applied.\r\n\r\n" + strings.Join(rows, "\r\n") + "\r\n"
	if err := s.mailer.Send(ctx, s.cfg.OwnerEmail, "TeleCrypt.io: billing reconciliation discrepancies", body); err != nil {
		state.notification = "failed"
		return &operationError{reason: "notification", err: httpdiag.WrapCause("provider discrepancy notification failed", err)}
	}
	state.notification = "succeeded"
	state.addLabel("notification")
	return nil
}

func (s *Sweeper) sweepDigest(ctx context.Context, users []masadmin.User, emails []masadmin.UserEmail, state *sweepState) error {
	if s.cfg.OwnerEmail == "" {
		return nil
	}
	cursor, found, err := s.store.JanitorDigestCursor(ctx)
	if err != nil {
		return &operationError{reason: "database", err: httpdiag.WrapCause("digest cursor read failed", err)}
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
				return &operationError{reason: "database", err: httpdiag.WrapCause("digest cursor advance failed", err)}
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
		return &operationError{reason: "notification", err: httpdiag.WrapCause("notification delivery failed", err)}
	}
	state.notification = "succeeded"
	state.addLabel("notification")
	if high.ID != "" {
		if err := s.store.SetJanitorDigestCursor(ctx, db.DigestCursor{CreatedAt: high.CreatedAt, EmailID: high.ID}); err != nil {
			return &operationError{reason: "database", err: httpdiag.WrapCause("digest cursor advance failed", err)}
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
