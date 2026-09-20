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
	events   []db.RunEvent
	actions  []db.LifecycleAction
	schedule map[string]bool
}

func (f *fakeStore) VerifyDeploymentIdentity(context.Context, string, string) error { return nil }
func (f *fakeStore) SyncLifecycleAccount(_ context.Context, mxid string, createdAt time.Time) error {
	if f.schedule != nil && f.schedule[mxid] {
		f.actions = append(f.actions, db.LifecycleAction{MXID: mxid, Revision: 1, Action: "suspend", DueAt: createdAt.Add(48 * time.Hour), DesiredUserType: stringPtr("wild")})
	}
	return nil
}
func (f *fakeStore) LifecycleActions(context.Context) ([]db.LifecycleAction, error) {
	return append([]db.LifecycleAction(nil), f.actions...), nil
}
func (f *fakeStore) ExecuteSuspension(ctx context.Context, mxid string, revision int64, apply func(context.Context, string) error) (bool, error) {
	for i, action := range f.actions {
		if action.MXID == mxid && action.Revision == revision && action.Action == "suspend" {
			if err := apply(ctx, "wild"); err != nil {
				return false, err
			}
			f.actions = append(f.actions[:i], f.actions[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}
func (f *fakeStore) StartRemoval(context.Context, string, int64) (bool, int64, error) {
	return false, 0, nil
}
func (f *fakeStore) FinishRemoval(context.Context, string, int64) (bool, error) { return false, nil }
func (f *fakeStore) JanitorDigestCursor(context.Context) (db.DigestCursor, bool, error) {
	return db.DigestCursor{}, false, nil
}

func stringPtr(value string) *string                                               { return &value }
func (f *fakeStore) SetJanitorDigestCursor(context.Context, db.DigestCursor) error { return nil }
func (f *fakeStore) InsertRunEvent(_ context.Context, event db.RunEvent) error {
	f.events = append(f.events, event)
	return nil
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

func (f *fakeDodo) Reconcile(context.Context) ([]Discrepancy, error) {
	f.calls++
	return []Discrepancy{{Subscription: "sub-1", Kind: "on_hold"}}, nil
}

func oldUser(username string) masadmin.User {
	return masadmin.User{ID: "01J00000000000000000000001", Username: username, CreatedAt: time.Now().Add(-49 * time.Hour)}
}

func testConfig() Config {
	return Config{ServerName: "stage.telecrypt.io", BillingEnvironment: "test", OwnerEmail: "owner@example.test"}
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
	if len(store.events) != 2 || store.events[1].LockedOrWouldLock != 1 {
		t.Fatalf("audit events = %#v", store.events)
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
