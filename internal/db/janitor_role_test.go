package db

import (
	"strings"
	"testing"
)

func validJanitorRoleAttributes() janitorRoleAttributes {
	return janitorRoleAttributes{
		currentRole: "telecrypt_janitor_user", sessionRole: "telecrypt_janitor_user",
		canLogin: true, inherit: false, superuser: false, createRole: false, createDB: false,
		replication: false, bypassRLS: false, membershipCount: 0,
	}
}

func TestValidateJanitorRoleAttributes(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*janitorRoleAttributes)
		wantErr string
	}{
		{name: "accepts locked role", mutate: func(*janitorRoleAttributes) {}},
		{name: "requires current session role", mutate: func(a *janitorRoleAttributes) { a.sessionRole = "other" }, wantErr: "current_user must equal session_user"},
		{name: "requires login", mutate: func(a *janitorRoleAttributes) { a.canLogin = false }, wantErr: "LOGIN"},
		{name: "requires noinherit", mutate: func(a *janitorRoleAttributes) { a.inherit = true }, wantErr: "NOINHERIT"},
		{name: "rejects superuser", mutate: func(a *janitorRoleAttributes) { a.superuser = true }, wantErr: "SUPERUSER"},
		{name: "rejects createrole", mutate: func(a *janitorRoleAttributes) { a.createRole = true }, wantErr: "CREATEROLE"},
		{name: "rejects createdb", mutate: func(a *janitorRoleAttributes) { a.createDB = true }, wantErr: "CREATEDB"},
		{name: "rejects replication", mutate: func(a *janitorRoleAttributes) { a.replication = true }, wantErr: "REPLICATION"},
		{name: "rejects bypassrls", mutate: func(a *janitorRoleAttributes) { a.bypassRLS = true }, wantErr: "BYPASSRLS"},
		{name: "rejects memberships", mutate: func(a *janitorRoleAttributes) { a.membershipCount = 1 }, wantErr: "zero role memberships"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attributes := validJanitorRoleAttributes()
			test.mutate(&attributes)
			err := validateJanitorRoleAttributes(attributes)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validateJanitorRoleAttributes() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateJanitorRoleAttributes() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}
