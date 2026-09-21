package janitor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/db"
	"github.com/TeleCrypt-io/controlplane/internal/masadmin"
)

type fakeMAS struct {
	users      []masadmin.User
	emails     []masadmin.UserEmail
	emailCalls int
}

func (f *fakeMAS) ListUsers(context.Context) ([]masadmin.User, error) { return f.users, nil }
func (f *fakeMAS) ListUserEmails(context.Context) ([]masadmin.UserEmail, error) {
	f.emailCalls++
	return f.emails, nil
}

type fakeSynapse struct {
	suspended []string
	userTypes map[string]string
}

func (f *fakeSynapse) SuspendUser(_ context.Context, mxid string, suspended bool) error {
	if suspended {
		f.suspended = append(f.suspended, mxid)
	}
	return nil
}
func (f *fakeSynapse) SetUserType(_ context.Context, mxid, userType string) error {
	if f.userTypes == nil {
		f.userTypes = make(map[string]string)
	}
	f.userTypes[mxid] = userType
	return nil
}
func (f *fakeSynapse) ReadUserType(_ context.Context, mxid string) (*string, error) {
	value := f.userTypes[mxid]
	return &value, nil
}

type fakeStore struct {
	actions  []db.LifecycleAction
	schedule map[string]bool
}

func (f *fakeStore) SyncLifecycleAccount(_ context.Context, mxid string, createdAt time.Time) error {
	if f.schedule != nil && f.schedule[mxid] {
		f.actions = append(f.actions, db.LifecycleAction{MXID: mxid, Action: "suspend", DueAt: createdAt.Add(48 * time.Hour), DesiredUserType: stringPtr("wild")})
	}
	return nil
}
func (f *fakeStore) LifecycleActions(context.Context) ([]db.LifecycleAction, error) {
	return append([]db.LifecycleAction(nil), f.actions...), nil
}
func (f *fakeStore) ExecuteSuspension(ctx context.Context, mxid string, apply func(context.Context, string) error) (bool, error) {
	for i, action := range f.actions {
		if action.MXID == mxid && action.Action == "suspend" {
			if err := apply(ctx, "wild"); err != nil {
				return false, err
			}
			f.actions = append(f.actions[:i], f.actions[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}
func (f *fakeStore) StartRemoval(context.Context, string) (bool, error)  { return false, nil }
func (f *fakeStore) FinishRemoval(context.Context, string) (bool, error) { return false, nil }
func (f *fakeStore) JanitorDigestCursor(context.Context) (db.DigestCursor, bool, error) {
	return db.DigestCursor{}, false, nil
}

func stringPtr(value string) *string                                               { return &value }
func (f *fakeStore) SetJanitorDigestCursor(context.Context, db.DigestCursor) error { return nil }
func (f *fakeStore) ProviderSubscriptionSnapshot(context.Context) ([]db.SubscriptionSnapshot, error) {
	return []db.SubscriptionSnapshot{{SubscriptionID: "sub-1", Status: "active"}}, nil
}

type fakeMailer struct {
	subject string
	body    string
}

func (f *fakeMailer) Send(_ context.Context, _ string, subject string, body string) error {
	f.subject, f.body = subject, body
	return nil
}

type fakeDodo struct{ calls int }

func (f *fakeDodo) Subscriptions(context.Context) ([]ProviderSubscription, error) {
	f.calls++
	return []ProviderSubscription{{SubscriptionID: "sub-1", Status: "on_hold"}}, nil
}

func oldUser(username string) masadmin.User {
	return masadmin.User{ID: "01J00000000000000000000001", Username: username, CreatedAt: time.Now().Add(-49 * time.Hour)}
}

func testConfig() Config {
	return Config{ServerName: "stage.telecrypt.io", BillingEnvironment: "test", OperatorEmail: "operator@example.test"}
}

func TestSweepSuspendsInitialFreeAccountThroughSynapse(t *testing.T) {
	mas := &fakeMAS{users: []masadmin.User{oldUser("free")}}
	synapse := &fakeSynapse{}
	store := &fakeStore{schedule: map[string]bool{"@free:stage.telecrypt.io": true}}
	sweeper := NewLifecycleSweeper(mas, synapse, store, &fakeMailer{}, nil, testConfig())
	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(synapse.suspended) != 1 || synapse.suspended[0] != "@free:stage.telecrypt.io" {
		t.Fatalf("suspensions = %#v", synapse.suspended)
	}
}

func TestSweepSkipsEmailAndExistingOperatorLock(t *testing.T) {
	now := time.Now().Add(-49 * time.Hour)
	mas := &fakeMAS{users: []masadmin.User{
		{ID: "01J00000000000000000000001", Username: "email", CreatedAt: now},
		{ID: "01J00000000000000000000002", Username: "operator", CreatedAt: now, LockedAt: &now},
	}}
	synapse := &fakeSynapse{}
	if err := NewLifecycleSweeper(mas, synapse, &fakeStore{}, &fakeMailer{}, nil, testConfig()).Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(synapse.suspended) != 0 {
		t.Fatalf("suspensions = %#v, want none", synapse.suspended)
	}
}

func TestSweepProviderReconciliationIsReadOnlyAndEmailOnly(t *testing.T) {
	mailer := &fakeMailer{}
	dodo := &fakeDodo{}
	if err := NewLifecycleSweeper(&fakeMAS{}, &fakeSynapse{}, &fakeStore{}, mailer, dodo, testConfig()).Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if dodo.calls != 1 || !strings.Contains(mailer.body, "no automatic correction") || !strings.Contains(mailer.subject, "reconciliation") {
		t.Fatalf("provider report calls=%d subject=%q body=%q", dodo.calls, mailer.subject, mailer.body)
	}
}

func TestSweepDoesNotRequireProviderForLifecycle(t *testing.T) {
	mas := &fakeMAS{users: []masadmin.User{oldUser("free")}}
	synapse := &fakeSynapse{}
	store := &fakeStore{schedule: map[string]bool{"@free:stage.telecrypt.io": true}}
	if err := NewLifecycleSweeper(mas, synapse, store, &fakeMailer{}, nil, testConfig()).Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(synapse.suspended) != 1 {
		t.Fatalf("suspensions = %#v", synapse.suspended)
	}
}

func TestCompareSubscriptionSnapshotsReportsOnlyMismatches(t *testing.T) {
	got := compareSubscriptionSnapshots(
		[]ProviderSubscription{{SubscriptionID: "same", Status: "active", ProviderProductID: "p1"}, {SubscriptionID: "provider", Status: "cancelled"}},
		[]db.SubscriptionSnapshot{{SubscriptionID: "same", Status: "active", ProviderProductID: "p1", TeamID: "team-same"}, {SubscriptionID: "cashier", Status: "on_hold", TeamID: "team-cashier"}},
	)
	if len(got) != 2 {
		t.Fatalf("discrepancies = %#v, want two", got)
	}
	seen := map[string]string{}
	for _, item := range got {
		seen[item.Subscription] = item.Kind
	}
	if seen["provider"] != "provider_only" || seen["cashier"] != "cashier_only" {
		t.Fatalf("discrepancies = %#v", got)
	}
	for _, item := range got {
		if item.Subscription == "cashier" && item.TeamID != "team-cashier" {
			t.Fatalf("cashier discrepancy team = %q", item.TeamID)
		}
	}
}
