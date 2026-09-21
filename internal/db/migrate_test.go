package db

import (
	"strings"
	"testing"
)

func TestValidateMigrationHistory(t *testing.T) {
	migrations := []migration{
		{name: "0001_one.sql", sha256: strings.Repeat("a", 64)},
		{name: "0002_two.sql", sha256: strings.Repeat("b", 64)},
	}
	tests := []struct {
		name    string
		history []migrationRecord
		wantErr string
	}{
		{name: "empty", history: nil},
		{name: "complete", history: []migrationRecord{{version: "0001_one.sql", sha256: strings.Repeat("a", 64)}, {version: "0002_two.sql", sha256: strings.Repeat("b", 64)}}},
		{name: "unknown", history: []migrationRecord{{version: "0003_unknown.sql", sha256: strings.Repeat("c", 64)}}, wantErr: "unknown"},
		{name: "changed", history: []migrationRecord{{version: "0001_one.sql", sha256: strings.Repeat("c", 64)}}, wantErr: "changed"},
		{name: "duplicate", history: []migrationRecord{{version: "0001_one.sql", sha256: strings.Repeat("a", 64)}, {version: "0001_one.sql", sha256: strings.Repeat("a", 64)}}, wantErr: "duplicate"},
		{name: "out of order", history: []migrationRecord{{version: "0002_two.sql", sha256: strings.Repeat("b", 64)}}, wantErr: "out of order"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMigrationHistory(tt.history, migrations)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateMigrationHistory() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateMigrationHistory() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
