package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateDeploymentProfile(t *testing.T) {
	for _, tc := range []struct {
		server, billing string
		valid           bool
	}{
		{"telecrypt.io", "test", true}, {"stage.telecrypt.io", "test", true}, {"telecrypt.io", "live", true},
		{"stage.telecrypt.io", "live", false}, {"preview.telecrypt.io", "test", false}, {"telecrypt.io", "production", false},
	} {
		t.Run(tc.server+"/"+tc.billing, func(t *testing.T) {
			if (ValidateDeploymentProfile(tc.server, tc.billing) == nil) != tc.valid {
				t.Fatalf("profile validity mismatch")
			}
		})
	}
}

func TestValidateRunEventStatesAndLabels(t *testing.T) {
	base := RunEvent{EventID: uuid.New(), RunID: uuid.New(), ServerName: "stage.telecrypt.io", BillingEnvironment: "test", NotificationStatus: "not_attempted"}
	if err := validateRunEvent(RunEvent{EventID: base.EventID, RunID: base.RunID, EventKind: "started", Status: "started", Outcome: "pending", Reason: "pending", ServerName: base.ServerName, BillingEnvironment: base.BillingEnvironment, NotificationStatus: "not_attempted"}); err != nil {
		t.Fatalf("valid started event: %v", err)
	}
	base.EventKind, base.Status, base.Outcome, base.Reason = "finished", "succeeded", "success", "disabled"
	base.LockedOrWouldLock = 1
	base.Labels = []string{"lock", "audit_finished"}
	if err := validateRunEvent(base); err != nil {
		t.Fatalf("valid finished event: %v", err)
	}
	base.Labels = []string{"not-allowlisted"}
	if err := validateRunEvent(base); err == nil || !strings.Contains(err.Error(), "allowlisted") {
		t.Fatalf("invalid label accepted: %v", err)
	}
	base.Labels = make([]string, 17)
	if err := validateRunEvent(base); err == nil || !strings.Contains(err.Error(), "sixteen") {
		t.Fatalf("oversized labels accepted: %v", err)
	}
}

func TestValidateRunEventAllowsMutationForAnyBillingProfile(t *testing.T) {
	for _, profile := range []struct {
		server, billing string
	}{
		{server: "stage.telecrypt.io", billing: "test"},
		{server: "telecrypt.io", billing: "live"},
	} {
		t.Run(profile.server+"/"+profile.billing, func(t *testing.T) {
			event := RunEvent{
				EventID: uuid.New(), RunID: uuid.New(), EventKind: "finished", Status: "succeeded",
				ServerName: profile.server, BillingEnvironment: profile.billing,
				Outcome: "success", Reason: "disabled", Considered: 1, LockedOrWouldLock: 1,
				NotificationStatus: "not_attempted",
			}
			if err := validateRunEvent(event); err != nil {
				t.Fatalf("validateRunEvent(%#v) rejected real sweep: %v", event, err)
			}
		})
	}
}

func TestDigestCursorValidationAndOrdering(t *testing.T) {
	valid := DigestCursor{CreatedAt: time.Now(), EmailID: "01J00000000000000000000000"}
	if !valid.Valid() {
		t.Fatal("valid cursor rejected")
	}
	for _, cursor := range []DigestCursor{{CreatedAt: time.Now(), EmailID: "not-ulid"}, {EmailID: valid.EmailID}} {
		if cursor.Valid() {
			t.Fatalf("invalid cursor accepted: %#v", cursor)
		}
	}
	if err := (&Store{}).SetJanitorDigestCursor(context.Background(), DigestCursor{CreatedAt: time.Now(), EmailID: "not-ulid"}); err == nil {
		t.Fatal("invalid cursor reached database")
	}
}
