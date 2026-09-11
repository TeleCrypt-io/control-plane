package janitor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/db"
	"github.com/TeleCrypt-io/controlplane/internal/masadmin"
)

const testServerName = "stage.telecrypt.io"

func testID(n byte) string { return "01J0000000000000000000000" + string('0'+n) }

type fakeMAS struct {
	users                                     []masadmin.User
	emails                                    []masadmin.UserEmail
	listUsersCalls, listEmailCalls, lockCalls int
	getUserCalls, emailChecks                 int
	listUsersErr, listEmailsErr               error
	getUserErrOnCall, emailErrOnCall          int
	lockErr                                   error
}

func (m *fakeMAS) ListUsers(context.Context) ([]masadmin.User, error) {
	m.listUsersCalls++
	if m.listUsersErr != nil {
		return nil, m.listUsersErr
	}
	return append([]masadmin.User(nil), m.users...), nil
}
func (m *fakeMAS) ListUserEmails(context.Context) ([]masadmin.UserEmail, error) {
	m.listEmailCalls++
	if m.listEmailsErr != nil {
		return nil, m.listEmailsErr
	}
	return append([]masadmin.UserEmail(nil), m.emails...), nil
}
func (m *fakeMAS) GetUser(_ context.Context, id string) (masadmin.User, error) {
	m.getUserCalls++
	if m.getUserErrOnCall == m.getUserCalls {
		return masadmin.User{}, errors.New("recheck failed")
	}
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return masadmin.User{}, errors.New("missing")
}
func (m *fakeMAS) HasUserEmail(_ context.Context, id string) (bool, error) {
	m.emailChecks++
	if m.emailErrOnCall == m.emailChecks {
		return false, errors.New("email recheck failed")
	}
	for _, e := range m.emails {
		if e.UserID == id {
			return true, nil
		}
	}
	return false, nil
}
func (m *fakeMAS) LockUser(_ context.Context, id string) error {
	m.lockCalls++
	if m.lockErr != nil {
		return m.lockErr
	}
	for i := range m.users {
		if m.users[i].ID == id {
			now := time.Now()
			m.users[i].LockedAt = &now
			return nil
		}
	}
	return errors.New("missing")
}

type fakeStore struct {
	exclusions                                    map[string]struct{}
	events                                        []db.RunEvent
	cursor                                        db.DigestCursor
	found                                         bool
	identityErr, viewErr, startedErr, finishedErr error
	identityCalls                                 int
	finishedContextCanceled                       bool
}

func (s *fakeStore) VerifyDeploymentIdentity(context.Context, string, string) error {
	s.identityCalls++
	return s.identityErr
}
func (s *fakeStore) LockExclusions(context.Context) (map[string]struct{}, error) {
	if s.viewErr != nil {
		return nil, s.viewErr
	}
	return s.exclusions, nil
}
func (s *fakeStore) JanitorDigestCursor(context.Context) (db.DigestCursor, bool, error) {
	return s.cursor, s.found, nil
}
func (s *fakeStore) SetJanitorDigestCursor(_ context.Context, c db.DigestCursor) error {
	s.cursor, s.found = c, true
	return nil
}
func (s *fakeStore) InsertRunEvent(ctx context.Context, event db.RunEvent) error {
	if event.EventKind == "started" && s.startedErr != nil {
		return s.startedErr
	}
	if event.EventKind == "finished" && s.finishedErr != nil {
		return s.finishedErr
	}
	if event.EventKind == "finished" {
		s.finishedContextCanceled = ctx.Err() != nil
	}
	s.events = append(s.events, event)
	return nil
}

type fakeMailer struct{ calls int }

func (m *fakeMailer) Send(context.Context, string, string, string) error { m.calls++; return nil }

func staleUser(id, username string) masadmin.User {
	return masadmin.User{ID: id, Username: username, CreatedAt: time.Now().Add(-72 * time.Hour)}
}

func testConfig() Config {
	return Config{ServerName: testServerName, BillingEnvironment: "test", OwnerEmail: "owner@example.test"}
}

func TestSweepTestProfileLocksEligibleAccountsAndWritesMutationAudit(t *testing.T) {
	mas := &fakeMAS{users: []masadmin.User{staleUser(testID(1), "paid"), staleUser(testID(2), "free")}}
	store := &fakeStore{exclusions: map[string]struct{}{"@paid:" + testServerName: {}}}
	sweeper := NewSweeper(mas, store, &fakeMailer{}, testConfig())
	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if mas.lockCalls != 1 {
		t.Fatalf("test profile MAS lock calls = %d, want one", mas.lockCalls)
	}
	if len(store.events) != 2 {
		t.Fatalf("audit events = %d, want started and finished", len(store.events))
	}
	finished := store.events[1]
	if finished.EventKind != "finished" || finished.Status != "succeeded" || finished.Outcome != "success" || finished.Reason != "disabled" || finished.LockedOrWouldLock != 1 {
		t.Fatalf("finished event = %#v", finished)
	}
	if finished.RunID != store.events[0].RunID || finished.EventID == store.events[0].EventID {
		t.Fatalf("audit IDs are not distinct per event/run")
	}
	for _, label := range finished.Labels {
		if label == "@paid:"+testServerName || label == "paid" {
			t.Fatalf("audit label contains an identifier: %q", label)
		}
	}
}

func TestSweepLocksWithoutOptionalOwnerDigest(t *testing.T) {
	mas := &fakeMAS{users: []masadmin.User{staleUser(testID(10), "free")}, listEmailsErr: errors.New("mail snapshot unavailable")}
	store := &fakeStore{exclusions: map[string]struct{}{}}
	cfg := Config{ServerName: testServerName, BillingEnvironment: "test"}
	if err := NewSweeper(mas, store, &fakeMailer{}, cfg).Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep without optional owner digest: %v", err)
	}
	if mas.lockCalls != 1 {
		t.Fatalf("MAS lock calls = %d, want one", mas.lockCalls)
	}
	if mas.listEmailCalls != 0 {
		t.Fatalf("MAS email listing calls = %d, want zero when digest is disabled", mas.listEmailCalls)
	}
	if got := store.events[1].Reason; got != "disabled" {
		t.Fatalf("finished reason = %q, want disabled", got)
	}
}

func TestSweepUsesExact48HourLockThreshold(t *testing.T) {
	now := time.Now()
	mas := &fakeMAS{users: []masadmin.User{
		{ID: testID(1), Username: "older", CreatedAt: now.Add(-48*time.Hour - time.Minute)},
		{ID: testID(2), Username: "younger", CreatedAt: now.Add(-48*time.Hour + time.Minute)},
	}}
	store := &fakeStore{exclusions: map[string]struct{}{}}

	if err := NewSweeper(mas, store, &fakeMailer{}, testConfig()).Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got := store.events[1].LockedOrWouldLock; got != 1 {
		t.Fatalf("accounts eligible at the 48-hour threshold = %d, want 1", got)
	}
	if mas.getUserCalls != 2 || mas.emailChecks != 2 {
		t.Fatalf("candidate checks = (user=%d, email=%d), want candidate and lock readback for the older account", mas.getUserCalls, mas.emailChecks)
	}
}

func TestSweepLiveLocksEligibleUserWithoutUnlockSurface(t *testing.T) {
	mas := &fakeMAS{users: []masadmin.User{staleUser(testID(3), "free")}}
	store := &fakeStore{exclusions: map[string]struct{}{}}
	cfg := Config{ServerName: "telecrypt.io", BillingEnvironment: "live", OwnerEmail: "owner@example.test"}
	sweeper := NewSweeper(mas, store, &fakeMailer{}, cfg)
	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if mas.lockCalls != 1 {
		t.Fatalf("MAS lock calls = %d, want one", mas.lockCalls)
	}
	if got := store.events[1].Reason; got != "disabled" {
		t.Fatalf("finished reason = %q, want disabled", got)
	}
	if store.identityCalls != 1 {
		t.Fatalf("deployment identity calls = %d, want startup check only", store.identityCalls)
	}
}

func TestSweepExcludesFixedMASServiceIdentityOnSupportedServers(t *testing.T) {
	for _, tc := range []struct {
		name, server, billing string
	}{
		{name: "live", server: "telecrypt.io", billing: "live"},
		{name: "stage test", server: testServerName, billing: "test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := staleUser(testID(1), "cashier-admin")
			human := staleUser(testID(2), "alice")
			similarlyNamed := staleUser(testID(3), "cashier-admin-helper")
			mas := &fakeMAS{users: []masadmin.User{service, human, similarlyNamed}}
			store := &fakeStore{exclusions: map[string]struct{}{}}
			cfg := Config{ServerName: tc.server, BillingEnvironment: tc.billing, OwnerEmail: "owner@example.test"}

			if err := NewSweeper(mas, store, &fakeMailer{}, cfg).Sweep(context.Background()); err != nil {
				t.Fatalf("Sweep: %v", err)
			}
			if service.LockedAt != nil || mas.users[0].LockedAt != nil {
				t.Fatal("fixed cashier-admin service identity was locked")
			}
			if mas.getUserCalls != 4 || mas.emailChecks != 4 {
				t.Fatalf("MAS candidate calls = (get=%d, email=%d), want human accounts only", mas.getUserCalls, mas.emailChecks)
			}
			finished := store.events[1]
			if got, want := finished.LockedOrWouldLock, int64(2); got != want {
				t.Fatalf("locked-or-would-lock = %d, want %d human accounts", got, want)
			}
			if mas.lockCalls != 2 {
				t.Fatalf("MAS lock calls = %d, want two human accounts", mas.lockCalls)
			}
			if mas.users[1].LockedAt == nil || mas.users[2].LockedAt == nil {
				t.Fatal("eligible human accounts were not locked")
			}
		})
	}
}

func TestSweepEntitlementViewFailurePreventsMASEnumeration(t *testing.T) {
	mas := &fakeMAS{}
	store := &fakeStore{viewErr: errors.New("private view unavailable")}
	if err := NewSweeper(mas, store, &fakeMailer{}, testConfig()).Sweep(context.Background()); err == nil {
		t.Fatal("Sweep accepted entitlement-view failure")
	}
	if mas.listUsersCalls != 0 || mas.listEmailCalls != 0 {
		t.Fatal("MAS enumeration occurred after entitlement-view failure")
	}
	if len(store.events) != 2 || store.events[1].Reason != "entitlement_view" {
		t.Fatalf("audit events = %#v", store.events)
	}
}

func TestSweepIdentityFailurePreventsAuditAndMASEnumeration(t *testing.T) {
	mas := &fakeMAS{}
	store := &fakeStore{identityErr: errors.New("identity mismatch")}
	if err := NewSweeper(mas, store, &fakeMailer{}, testConfig()).Sweep(context.Background()); err == nil {
		t.Fatal("Sweep accepted deployment identity failure")
	}
	if mas.listUsersCalls != 0 || mas.listEmailCalls != 0 || len(store.events) != 0 {
		t.Fatalf("identity failure proceeded past authorization: MAS calls=(%d,%d), events=%d", mas.listUsersCalls, mas.listEmailCalls, len(store.events))
	}
}

func TestSweepRequiredAuditWriteFailureIsNonSuccess(t *testing.T) {
	store := &fakeStore{startedErr: errors.New("audit unavailable")}
	if err := NewSweeper(&fakeMAS{}, store, &fakeMailer{}, testConfig()).Sweep(context.Background()); err == nil {
		t.Fatal("Sweep accepted started-audit failure")
	}
	if len(store.events) != 0 {
		t.Fatal("recorded audit event despite failed started write")
	}

	store = &fakeStore{}
	store.finishedErr = errors.New("audit unavailable")
	mas := &fakeMAS{users: []masadmin.User{staleUser(testID(4), "free")}}
	if err := NewSweeper(mas, store, &fakeMailer{}, testConfig()).Sweep(context.Background()); err == nil {
		t.Fatal("Sweep accepted finished-audit failure")
	}
	if len(store.events) != 1 || store.events[0].EventKind != "started" {
		t.Fatalf("events after finished failure = %#v", store.events)
	}
}

func TestSweepRejectsUnsupportedOrMismatchedProfile(t *testing.T) {
	for _, cfg := range []Config{{ServerName: "preview.telecrypt.io", BillingEnvironment: "test"}, {ServerName: testServerName, BillingEnvironment: "live"}} {
		store := &fakeStore{}
		if err := NewSweeper(&fakeMAS{}, store, &fakeMailer{}, cfg).Sweep(context.Background()); err == nil {
			t.Fatal("Sweep accepted invalid billing profile")
		}
		if len(store.events) != 0 {
			t.Fatal("invalid profile emitted an audit event")
		}
	}
}

func TestSweepAttemptsFinishedAuditAfterCancellationWithBoundedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := &fakeStore{}
	mas := &fakeMAS{users: []masadmin.User{staleUser(testID(5), "free")}}
	if err := NewSweeper(mas, store, &fakeMailer{}, testConfig()).Sweep(ctx); err == nil {
		t.Fatal("canceled Sweep unexpectedly succeeded")
	}
	if len(store.events) != 2 || store.events[1].EventKind != "finished" || store.events[1].Reason != "cancelled" {
		t.Fatalf("canceled Sweep events = %#v, want started and cancelled finished events", store.events)
	}
	if store.finishedContextCanceled {
		t.Fatal("finished audit insert used an already-canceled context")
	}
}

func TestSweepMASPageFailureStopsBeforeMutationAndAuditsFailure(t *testing.T) {
	store := &fakeStore{}
	mas := &fakeMAS{listUsersErr: errors.New("users page failed")}
	if err := NewSweeper(mas, store, &fakeMailer{}, Config{ServerName: "telecrypt.io", BillingEnvironment: "live"}).Sweep(context.Background()); err == nil {
		t.Fatal("Sweep accepted MAS page failure")
	}
	if mas.lockCalls != 0 || mas.listEmailCalls != 0 {
		t.Fatal("MAS mutation or later page fetch occurred after users page failure")
	}
	if len(store.events) != 2 || store.events[1].Reason != "mas" {
		t.Fatalf("events = %#v, want failed MAS audit", store.events)
	}
}

func TestSweepCandidateRecheckFailureStopsBeforeLaterMutation(t *testing.T) {
	mas := &fakeMAS{users: []masadmin.User{staleUser(testID(6), "first"), staleUser(testID(7), "second")}, getUserErrOnCall: 1}
	store := &fakeStore{exclusions: map[string]struct{}{}}
	if err := NewSweeper(mas, store, &fakeMailer{}, Config{ServerName: "telecrypt.io", BillingEnvironment: "live"}).Sweep(context.Background()); err == nil {
		t.Fatal("Sweep accepted candidate recheck failure")
	}
	if mas.getUserCalls != 1 || mas.lockCalls != 0 {
		t.Fatalf("candidate calls = (get=%d, lock=%d), want one recheck and no locks", mas.getUserCalls, mas.lockCalls)
	}
	if len(store.events) != 2 || store.events[1].Reason != "mas" {
		t.Fatalf("events = %#v, want failed candidate-recheck audit", store.events)
	}
}

func TestSweepLockReadbackFailureStopsBeforeLaterMutation(t *testing.T) {
	mas := &fakeMAS{users: []masadmin.User{staleUser(testID(8), "first"), staleUser(testID(9), "second")}, getUserErrOnCall: 2}
	store := &fakeStore{exclusions: map[string]struct{}{}}
	if err := NewSweeper(mas, store, &fakeMailer{}, Config{ServerName: "telecrypt.io", BillingEnvironment: "live"}).Sweep(context.Background()); err == nil {
		t.Fatal("Sweep accepted lock readback failure")
	}
	if mas.getUserCalls != 2 || mas.lockCalls != 1 {
		t.Fatalf("candidate calls = (get=%d, lock=%d), want one lock then stop", mas.getUserCalls, mas.lockCalls)
	}
	if len(store.events) != 2 || store.events[1].Reason != "lock_readback" {
		t.Fatalf("events = %#v, want failed lock-readback audit", store.events)
	}
}
