// Package janitor implements one scheduled lifecycle-maintenance run. It has no HTTP server.
// Cashier owns entitlement and lifecycle state; Janitor performs the external maintenance work.
package janitor

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/httpdiag"
	"github.com/TeleCrypt-io/controlplane/internal/masadmin"
)

type Config struct {
	ServerName    string
	OperatorEmail string
}

type masAdminClient interface {
	ListUsers(context.Context) ([]masadmin.User, error)
	ListUserEmails(context.Context) ([]masadmin.UserEmail, error)
}

type masRemovalClient interface {
	DeactivateUser(context.Context, string) error
}

type mediaRemovalClient interface {
	DeleteAllMedia(context.Context, string) error
}

// Discrepancy is intentionally provider-neutral. Janitor reports it to the operator and does not
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
	Subscriptions(context.Context) ([]ProviderSubscription, error)
}

type Mailer interface {
	Send(context.Context, string, string, string) error
}

type Sweeper struct {
	mas     masAdminClient
	synapse any
	cashier cashierAPI
	mailer  Mailer
	dodo    DodoReconciler
	cfg     Config
}

func NewLifecycleSweeper(mas masAdminClient, synapse any, cashier cashierAPI, mailer Mailer, dodo DodoReconciler, cfg Config) *Sweeper {
	return &Sweeper{mas: mas, synapse: synapse, cashier: cashier, mailer: mailer, dodo: dodo, cfg: cfg}
}

// Sweep performs exactly one complete nightly run. Dodo reconciliation and email are read-only
// reporting paths; Cashier owns lifecycle and subscription state through its private API.
func (s *Sweeper) Sweep(ctx context.Context) error {
	users, err := s.mas.ListUsers(ctx)
	if err != nil {
		return httpdiag.WrapCause("janitor: list users failed", err)
	}
	if err := s.sweepAuthoritativeLifecycle(ctx, users); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return httpdiag.WrapCause("janitor: sweep canceled", ctx.Err())
	}
	if err := s.sweepProvider(ctx); err != nil {
		return err
	}
	var emails []masadmin.UserEmail
	if s.cfg.OperatorEmail != "" {
		emails, err = s.mas.ListUserEmails(ctx)
		if err != nil {
			return httpdiag.WrapCause("janitor: list user emails failed", err)
		}
	}
	if err := s.sweepDigest(ctx, users, emails); err != nil {
		return httpdiag.WrapCause("janitor: digest failed", err)
	}
	return nil
}

func (s *Sweeper) sweepAuthoritativeLifecycle(ctx context.Context, users []masadmin.User) error {
	for _, snapshot := range users {
		mxid := s.mxid(snapshot.Username)
		if mxid == "" || snapshot.DeactivatedAt != nil {
			continue
		}
		if err := s.cashier.SyncLifecycleAccount(ctx, mxid, snapshot.CreatedAt); err != nil {
			return httpdiag.WrapCause("janitor: synchronize lifecycle account", err)
		}
	}
	actions, err := s.cashier.LifecycleActions(ctx)
	if err != nil {
		return httpdiag.WrapCause("janitor: read lifecycle actions", err)
	}
	usersByUsername := make(map[string]masadmin.User, len(users))
	for _, user := range users {
		usersByUsername[user.Username] = user
	}
	for _, action := range actions {
		if ctx.Err() != nil {
			return httpdiag.WrapCause("janitor: lifecycle sweep canceled", ctx.Err())
		}
		switch action.Action {
		case "suspend":
			if _, err := s.cashier.ExecuteSuspension(ctx, action.MXID); err != nil {
				return httpdiag.WrapCause("janitor: suspend lifecycle account", err)
			}
		case "start_removal":
			started, err := s.cashier.StartRemoval(ctx, action.MXID)
			if err != nil {
				return httpdiag.WrapCause("janitor: start lifecycle removal", err)
			}
			if started {
				if err := s.finishExternalRemoval(ctx, action.MXID, usersByUsername); err != nil {
					return err
				}
				if _, err := s.cashier.FinishRemoval(ctx, action.MXID); err != nil {
					return httpdiag.WrapCause("janitor: finish lifecycle removal", err)
				}
			}
		case "finish_removal":
			if err := s.finishExternalRemoval(ctx, action.MXID, usersByUsername); err != nil {
				return err
			}
			if _, err := s.cashier.FinishRemoval(ctx, action.MXID); err != nil {
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

func (s *Sweeper) mxid(username string) string {
	if !masadmin.ValidMXID(username, s.cfg.ServerName) {
		return ""
	}
	return fmt.Sprintf("@%s:%s", username, s.cfg.ServerName)
}

func (s *Sweeper) sweepProvider(ctx context.Context) error {
	if s.dodo == nil {
		return nil
	}
	provider, err := s.dodo.Subscriptions(ctx)
	if err != nil {
		return httpdiag.WrapCause("provider reconciliation failed", err)
	}
	local, err := s.cashier.ProviderSubscriptionSnapshot(ctx)
	if err != nil {
		return httpdiag.WrapCause("Cashier subscription snapshot failed", err)
	}
	discrepancies := compareSubscriptionSnapshots(provider, local)
	if len(discrepancies) == 0 || s.cfg.OperatorEmail == "" {
		return nil
	}
	rows := make([]string, 0, len(discrepancies))
	for _, discrepancy := range discrepancies {
		rows = append(rows, fmt.Sprintf("%s %s %s", discrepancy.TeamID, discrepancy.Subscription, discrepancy.Kind))
	}
	sort.Strings(rows)
	body := "Dodo reconciliation found discrepancies; no automatic correction was applied.\r\n\r\n" + strings.Join(rows, "\r\n") + "\r\n"
	if err := s.mailer.Send(ctx, s.cfg.OperatorEmail, "TeleCrypt.io: billing reconciliation discrepancies", body); err != nil {
		return httpdiag.WrapCause("provider discrepancy notification failed", err)
	}
	return nil
}

func compareSubscriptionSnapshots(provider []ProviderSubscription, local []SubscriptionSnapshot) []Discrepancy {
	providerByID := make(map[string]ProviderSubscription, len(provider))
	for _, item := range provider {
		if item.SubscriptionID != "" {
			providerByID[item.SubscriptionID] = item
		}
	}
	localByID := make(map[string]SubscriptionSnapshot, len(local))
	for _, item := range local {
		if item.SubscriptionID != "" {
			localByID[item.SubscriptionID] = item
		}
	}
	var discrepancies []Discrepancy
	for id, item := range providerByID {
		current, found := localByID[id]
		if !found {
			discrepancies = append(discrepancies, Discrepancy{TeamID: item.TeamID, Subscription: id, Kind: "provider_only", Detail: item.Status})
			continue
		}
		if item.Status != current.Status || (item.ProviderProductID != "" && current.ProviderProductID != "" && item.ProviderProductID != current.ProviderProductID) {
			discrepancies = append(discrepancies, Discrepancy{TeamID: current.TeamID, Subscription: id, Kind: "state_mismatch", Detail: item.Status + " != " + current.Status})
		}
		delete(localByID, id)
	}
	for id, item := range localByID {
		discrepancies = append(discrepancies, Discrepancy{TeamID: item.TeamID, Subscription: id, Kind: "cashier_only", Detail: item.Status})
	}
	return discrepancies
}

func (s *Sweeper) sweepDigest(ctx context.Context, users []masadmin.User, emails []masadmin.UserEmail) error {
	if s.cfg.OperatorEmail == "" {
		return nil
	}
	cursor, found, err := s.cashier.JanitorDigestCursor(ctx)
	if err != nil {
		return httpdiag.WrapCause("digest cursor read failed", err)
	}
	if !found {
		cursor = DigestCursor{CreatedAt: time.Unix(0, 0).UTC()}
	} else if !cursor.Valid() {
		return fmt.Errorf("digest cursor is invalid")
	}
	usersByID := make(map[string]masadmin.User, len(users))
	for _, user := range users {
		if !validEventID(user.ID) || user.Username == "" || user.CreatedAt.IsZero() {
			return fmt.Errorf("digest user snapshot is invalid")
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
			return fmt.Errorf("digest email snapshot is invalid")
		}
		if after(email.CreatedAt, email.ID) {
			if _, ok := usersByID[email.UserID]; !ok {
				return fmt.Errorf("digest snapshots disagree")
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
			return fmt.Errorf("digest snapshots disagree")
		}
		mxid := s.mxid(user.Username)
		if mxid == "" {
			return fmt.Errorf("digest user identity is invalid")
		}
		candidates = append(candidates, candidate{mxid: mxid, userCreatedAt: user.CreatedAt, email: email})
	}
	if len(candidates) == 0 {
		if high.ID != "" {
			if err := s.cashier.SetJanitorDigestCursor(ctx, DigestCursor{CreatedAt: high.CreatedAt, EmailID: high.ID}); err != nil {
				return httpdiag.WrapCause("digest cursor advance failed", err)
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
	if err := s.mailer.Send(ctx, s.cfg.OperatorEmail, fmt.Sprintf("TeleCrypt.io: %d new sign-up(s) awaiting review", len(candidates)), body.String()); err != nil {
		return httpdiag.WrapCause("notification delivery failed", err)
	}
	if high.ID != "" {
		if err := s.cashier.SetJanitorDigestCursor(ctx, DigestCursor{CreatedAt: high.CreatedAt, EmailID: high.ID}); err != nil {
			return httpdiag.WrapCause("digest cursor advance failed", err)
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
