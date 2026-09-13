package db

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenJanitorPoolUsesPrivateSchema(t *testing.T) {
	pool, err := OpenJanitorPool(context.Background(), "postgres://janitor:secret@example.test/database?sslmode=require&connect_timeout=5&application_name=janitor")
	if err != nil {
		t.Fatalf("OpenJanitorPool: %v", err)
	}
	defer pool.Close()
	if got, want := pool.Config().ConnConfig.RuntimeParams["search_path"], janitorSearchPath; got != want {
		t.Fatalf("search_path = %q, want %q", got, want)
	}
	if _, present := pool.Config().ConnConfig.RuntimeParams["options"]; present {
		t.Fatal("OpenJanitorPool retained arbitrary connection options")
	}
}

func TestOpenJanitorPoolRejectsServicefileBeforeFilesystemRead(t *testing.T) {
	serviceFile := filepath.Join(t.TempDir(), "service.conf")
	if err := os.WriteFile(serviceFile, []byte("[redirected]\nhost=redirected.example\n"), 0o600); err != nil {
		t.Fatalf("write service file: %v", err)
	}
	databaseURL := "postgres://janitor:secret@example.test/database?servicefile=" + url.QueryEscape(serviceFile) + "&service=redirected"
	_, err := OpenJanitorPool(context.Background(), databaseURL)
	if err == nil || !strings.Contains(err.Error(), "query parameter") {
		t.Fatalf("OpenJanitorPool error = %v, want pre-parse servicefile rejection", err)
	}
	if strings.Contains(err.Error(), "failed to read service") {
		t.Fatalf("OpenJanitorPool parsed servicefile before rejecting it: %v", err)
	}
}

func TestOpenJanitorPoolRejectsAmbientPostgresSettings(t *testing.T) {
	t.Setenv("PGSERVICE", "redirected")
	_, err := OpenJanitorPool(context.Background(), "postgres://janitor:secret@example.test/database")
	if err == nil || !strings.Contains(err.Error(), "ambient PGSERVICE") {
		t.Fatalf("OpenJanitorPool error = %v, want ambient PGSERVICE rejection", err)
	}
}

func TestOpenJanitorPoolRejectsPresentEmptyAmbientPostgresSettings(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	_, err := OpenJanitorPool(context.Background(), "postgres://janitor:secret@example.test/database")
	if err == nil || !strings.Contains(err.Error(), "ambient PGSERVICE") {
		t.Fatalf("OpenJanitorPool error = %v, want present empty PGSERVICE rejection", err)
	}
}
