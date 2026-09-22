package janitor

import (
	"context"
	"strings"
	"testing"
	"time"

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
}

type fakeCashier struct {
	actions     []LifecycleAction
	schedule    map[string]bool
	suspended   []string
	startCalls  []string
	finishCalls []string
}

func (f *fakeCashier) SyncLifecycleAccount(_ context.Context, mxid string, createdAt time.Time) error {
	if f.schedule != nil && f.schedule[mxid] {
		f.actions = append(f.actions, LifecycleAction{MXID: mxid, Action: "suspend", DueAt: createdAt.Add(48 * time.Hour)})
	}
	return nil
}
func (f *fakeCashier) LifecycleActions(context.Context) ([]LifecycleAction, error) {
	return append([]LifecycleAction(nil), f.actions...), nil
}
func (f *fakeCashier) ExecuteSuspension(_ context.Context, mxid string) (bool, error) {
	for i, action := range f.actions {
		if action.MXID == mxid && action.Action == "suspend" {
			f.suspended = append(f.suspended, mxid)
			f.actions = append(f.actions[:i], f.actions[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}
func (f *fakeCashier) StartRemoval(_ context.Context, mxid string) (bool, error) {
	f.startCalls = append(f.startCalls, mxid)
	return false, nil
}
func (f *fakeCashier) FinishRemoval(_ context.Context, mxid string) (bool, error) {
	f.finishCalls = append(f.finishCalls, mxid)
	return false, nil
}
func (f *fakeCashier) JanitorDigestCursor(context.Context) (DigestCursor, bool, error) {
	return DigestCursor{}, false, nil
}
func (f *fakeCashier) SetJanitorDigestCursor(context.Context, DigestCursor) error { return nil }
func (f *fakeCashier) ProviderSubscriptionSnapshot(context.Context) ([]SubscriptionSnapshot, error) {
	return []SubscriptionSnapshot{{SubscriptionID: "sub-1", Status: "active"}}, nil
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
	return Config{ServerName: "stage.telecrypt.io", OperatorEmail: "operator@example.test"}
}

func TestSweepRequestsInitialFreeAccountSuspensionFromCashier(t *testing.T) {
	mas := &fakeMAS{users: []masadmin.User{oldUser("free")}}
	synapse := &fakeSynapse{}
	cashier := &fakeCashier{schedule: map[string]bool{"@free:stage.telecrypt.io": true}}
	sweeper := NewLifecycleSweeper(mas, synapse, cashier, &fakeMailer{}, nil, testConfig())
	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(cashier.suspended) != 1 || cashier.suspended[0] != "@free:stage.telecrypt.io" {
		t.Fatalf("Cashier suspension requests = %#v", cashier.suspended)
	}
}

func TestSweepSkipsEmailAndExistingOperatorLock(t *testing.T) {
	now := time.Now().Add(-49 * time.Hour)
	mas := &fakeMAS{users: []masadmin.User{
		{ID: "01J00000000000000000000001", Username: "email", CreatedAt: now},
		{ID: "01J00000000000000000000002", Username: "operator", CreatedAt: now, LockedAt: &now},
	}}
	synapse := &fakeSynapse{}
	cashier := &fakeCashier{}
	if err := NewLifecycleSweeper(mas, synapse, cashier, &fakeMailer{}, nil, testConfig()).Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(cashier.suspended) != 0 {
		t.Fatalf("suspensions = %#v, want none", cashier.suspended)
	}
}

func TestSweepProviderReconciliationIsReadOnlyAndEmailOnly(t *testing.T) {
	mailer := &fakeMailer{}
	dodo := &fakeDodo{}
	if err := NewLifecycleSweeper(&fakeMAS{}, &fakeSynapse{}, &fakeCashier{}, mailer, dodo, testConfig()).Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if dodo.calls != 1 || !strings.Contains(mailer.body, "no automatic correction") || !strings.Contains(mailer.subject, "reconciliation") {
		t.Fatalf("provider report calls=%d subject=%q body=%q", dodo.calls, mailer.subject, mailer.body)
	}
}

func TestSweepDoesNotRequireProviderForLifecycle(t *testing.T) {
	mas := &fakeMAS{users: []masadmin.User{oldUser("free")}}
	synapse := &fakeSynapse{}
	cashier := &fakeCashier{schedule: map[string]bool{"@free:stage.telecrypt.io": true}}
	if err := NewLifecycleSweeper(mas, synapse, cashier, &fakeMailer{}, nil, testConfig()).Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(cashier.suspended) != 1 {
		t.Fatalf("suspensions = %#v", cashier.suspended)
	}
}

func TestCompareSubscriptionSnapshotsReportsOnlyMismatches(t *testing.T) {
	got := compareSubscriptionSnapshots(
		[]ProviderSubscription{{SubscriptionID: "same", Status: "active", ProviderProductID: "p1"}, {SubscriptionID: "provider", Status: "cancelled"}},
		[]SubscriptionSnapshot{{SubscriptionID: "same", Status: "active", ProviderProductID: "p1", TeamID: "team-same"}, {SubscriptionID: "cashier", Status: "on_hold", TeamID: "team-cashier"}},
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
