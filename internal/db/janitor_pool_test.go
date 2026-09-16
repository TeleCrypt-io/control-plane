package db

import (
	"context"
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
