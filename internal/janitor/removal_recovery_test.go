package janitor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/masadmin"
)

type recoveryMAS struct {
	fakeMAS
	fail        bool
	deactivated map[string]bool
}

func (m *recoveryMAS) DeactivateUser(_ context.Context, id string) error {
	if m.fail && id == "bad" {
		return errors.New("deactivation interrupted")
	}
	m.deactivated[id] = true
	for i := range m.users {
		if m.users[i].ID == id {
			now := time.Now()
			m.users[i].DeactivatedAt = &now
		}
	}
	return nil
}

type recoveryMedia struct {
	fail    bool
	deleted map[string]bool
}

func (m *recoveryMedia) DeleteAllMedia(_ context.Context, mxid string) error {
	if m.fail && strings.Contains(mxid, "bad") {
		return errors.New("deletion interrupted")
	}
	m.deleted[mxid] = true
	return nil
}

type recoveryCashier struct {
	fakeCashier
	fail         bool
	storage      []string
	storageCalls []string
	storageFail  bool
}

func (c *recoveryCashier) StartRemoval(_ context.Context, mxid string) (bool, error) {
	for i := range c.actions {
		if c.actions[i].MXID == mxid {
			c.actions[i].Action = "finish_removal"
		}
	}
	return true, nil
}
func (c *recoveryCashier) FinishRemoval(_ context.Context, mxid string) (bool, error) {
	if c.fail && strings.Contains(mxid, "bad") {
		return false, errors.New("completion interrupted")
	}
	for i, a := range c.actions {
		if a.MXID == mxid {
			c.actions = append(c.actions[:i], c.actions[i+1:]...)
			break
		}
	}
	c.finishCalls = append(c.finishCalls, mxid)
	return true, nil
}
func (c *recoveryCashier) StorageAccounts(context.Context) ([]string, error) { return c.storage, nil }
func (c *recoveryCashier) ReconcileStorage(_ context.Context, mxid string) (StorageReconciliation, error) {
	c.storageCalls = append(c.storageCalls, mxid)
	if c.storageFail && mxid == "bad" {
		return StorageReconciliation{}, errors.New("inventory unavailable")
	}
	return StorageReconciliation{BeforeBytes: 10, AfterBytes: 20, CorrectedRecords: 1}, nil
}

func TestRemovalRetriesEveryStepAndContinuesIndependentMaintenance(t *testing.T) {
	for _, step := range []string{"media", "MAS", "completion"} {
		t.Run(step, func(t *testing.T) {
			mas := &recoveryMAS{fakeMAS: fakeMAS{users: []masadmin.User{{ID: "bad", Username: "bad", CreatedAt: time.Now()}, {ID: "good", Username: "good", CreatedAt: time.Now()}}}, fail: step == "MAS", deactivated: map[string]bool{}}
			media := &recoveryMedia{fail: step == "media", deleted: map[string]bool{}}
			cashier := &recoveryCashier{fakeCashier: fakeCashier{actions: []LifecycleAction{{MXID: "@bad:stage.telecrypt.io", Action: "start_removal"}, {MXID: "@good:stage.telecrypt.io", Action: "start_removal"}}}, fail: step == "completion", storage: []string{"healthy"}}
			provider := &fakeDodo{}
			sweeper := NewLifecycleSweeper(mas, media, cashier, &fakeMailer{}, provider, Config{ServerName: "stage.telecrypt.io"})
			err := sweeper.Sweep(context.Background())
			if err == nil || !strings.Contains(err.Error(), "@bad:") || len(cashier.finishCalls) != 1 || cashier.finishCalls[0] != "@good:stage.telecrypt.io" || provider.calls != 1 || len(cashier.storageCalls) != 1 {
				t.Fatalf("isolated failure: %v %+v", err, cashier)
			}
			mas.fail = false
			media.fail = false
			cashier.fail = false
			if err := sweeper.Sweep(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(cashier.actions) != 0 || !mas.deactivated["bad"] || !media.deleted["@bad:stage.telecrypt.io"] {
				t.Fatal("removal retry incomplete")
			}
		})
	}
}

func TestStorageFailureReportsAndContinuesAccountsAndProvider(t *testing.T) {
	cashier := &recoveryCashier{storage: []string{"bad", "healthy"}, storageFail: true}
	mail := &fakeMailer{}
	sweeper := NewLifecycleSweeper(&fakeMAS{}, &fakeSynapse{}, cashier, mail, nil, testConfig())
	err := sweeper.Sweep(context.Background())
	if err == nil || len(cashier.storageCalls) != 2 || !strings.Contains(mail.body, "FAILED") || !strings.Contains(mail.body, "+10 bytes") {
		t.Fatalf("storage report: %v %s", err, mail.body)
	}
	cashier.storageFail = false
	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
}
