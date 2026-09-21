package db

import (
	"context"
	"testing"
	"time"
)

func TestValidateDeploymentProfile(t *testing.T) {
	for _, tc := range []struct {
		server, billing string
		valid           bool
	}{
		{"example.invalid", "test", true}, {"preview.example.invalid", "test", true}, {"example.invalid", "live", true},
		{"bad host", "test", false}, {"", "test", false}, {"example.invalid", "production", false},
	} {
		t.Run(tc.server+"/"+tc.billing, func(t *testing.T) {
			if (ValidateDeploymentProfile(tc.server, tc.billing) == nil) != tc.valid {
				t.Fatalf("profile validity mismatch")
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
