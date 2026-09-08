package db

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdvisoryCleanupContextUsesSharedBoundedPolicy(t *testing.T) {
	cleanup, cancel := boundedCleanupContext(context.Background())
	defer cancel()

	deadline, ok := cleanup.Deadline()
	if !ok {
		t.Fatal("cleanup context has no deadline")
	}
	remaining := deadline.Sub(time.Now())
	if remaining <= 0 || remaining > advisoryLockCleanupTimeout {
		t.Fatalf("cleanup deadline window = %s, want (0, %s]", remaining, advisoryLockCleanupTimeout)
	}

	parent, stopParent := context.WithCancel(context.Background())
	defer stopParent()
	child, cancelChild := boundedCleanupContext(parent)
	defer cancelChild()
	stopParent()
	if child.Err() == nil {
		t.Fatal("cleanup context did not inherit parent cancellation")
	}
}

func TestJanitorInvocationLockIsSingleFlight(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres test")
	}
	ctx := context.Background()
	pool, err := OpenJanitorPool(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenJanitorPool: %v", err)
	}
	defer pool.Close()

	first, err := AcquireJanitorInvocationLock(ctx, pool)
	if err != nil {
		t.Fatalf("first AcquireJanitorInvocationLock: %v", err)
	}
	defer func() {
		if err := first.Release(context.Background()); err != nil {
			t.Errorf("first Release: %v", err)
		}
	}()

	second, err := AcquireJanitorInvocationLock(ctx, pool)
	if err == nil || !strings.Contains(err.Error(), ErrJanitorAlreadyRunning.Error()) {
		if second != nil {
			if releaseErr := second.Release(context.Background()); releaseErr != nil {
				t.Errorf("second Release: %v", releaseErr)
			}
		}
		t.Fatalf("second AcquireJanitorInvocationLock = %v, want already-running error", err)
	}

	if err := first.Release(context.Background()); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	third, err := AcquireJanitorInvocationLock(ctx, pool)
	if err != nil {
		t.Fatalf("third AcquireJanitorInvocationLock after release: %v", err)
	}
	if err := third.Release(context.Background()); err != nil {
		t.Fatalf("third Release: %v", err)
	}
}

// TestJanitorInvocationLockTwoProcessesBlocksAllPostLockWork runs two independent test-binary
// processes against one PostgreSQL session lock. The winner performs the same bind/migrate
// sequence as cmd/janitor and then holds the lease. The loser must exit at the lock gate, before
// even the bind marker, migration, or the markers representing external MAS/SMTP actions.
func TestJanitorInvocationLockTwoProcessesBlocksAllPostLockWork(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres test")
	}

	ctx := context.Background()
	pool, err := OpenJanitorPool(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenJanitorPool: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `
		DROP SCHEMA IF EXISTS cashier CASCADE;
		DROP SCHEMA IF EXISTS janitor CASCADE;
		CREATE SCHEMA janitor;
		CREATE SCHEMA cashier;
		CREATE TABLE cashier.identity_source (
			singleton BOOLEAN PRIMARY KEY,
			server_name TEXT NOT NULL,
			billing_environment TEXT NOT NULL
		);
		INSERT INTO cashier.identity_source (singleton, server_name, billing_environment)
		VALUES (TRUE, 'telecrypt.io', 'live');
		CREATE VIEW cashier.janitor_deployment_identity AS
			SELECT server_name, billing_environment FROM cashier.identity_source;
		CREATE VIEW cashier.janitor_lock_exclusions AS
			SELECT CAST(NULL AS TEXT) AS mxid WHERE FALSE;
	`); err != nil {
		t.Fatalf("prepare single-flight database: %v", err)
	}

	actionLog := filepath.Join(t.TempDir(), "actions.log")
	env := append(os.Environ(),
		"JANITOR_INVOCATION_CHILD=1",
		"JANITOR_ACTION_LOG="+actionLog,
	)

	winnerStdin, winnerStdinWriter := io.Pipe()
	winner := exec.Command(os.Args[0], "-test.run=^TestJanitorInvocationLockChild$")
	winner.Env = append(env, "JANITOR_CHILD_HOLD=1")
	winner.Stdin = winnerStdin
	winnerStdout, err := winner.StdoutPipe()
	if err != nil {
		winnerStdinWriter.Close()
		t.Fatalf("winner stdout: %v", err)
	}
	var winnerStderr bytes.Buffer
	winner.Stderr = &winnerStderr
	if err := winner.Start(); err != nil {
		winnerStdinWriter.Close()
		t.Fatalf("start winner: %v", err)
	}
	winnerDone := make(chan error, 1)
	go func() { winnerDone <- winner.Wait() }()
	winnerFinished := false
	t.Cleanup(func() {
		if winnerFinished {
			return
		}
		_ = winnerStdinWriter.Close()
		select {
		case <-winnerDone:
		case <-time.After(2 * time.Second):
			_ = winner.Process.Kill()
			select {
			case <-winnerDone:
			case <-time.After(2 * time.Second):
			}
		}
	})

	winnerReady := make(chan string, 1)
	go func() {
		reader := bufio.NewReader(winnerStdout)
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			winnerReady <- "read error: " + readErr.Error()
			return
		}
		winnerReady <- strings.TrimSpace(line)
		_, _ = io.Copy(io.Discard, reader)
	}()
	select {
	case line := <-winnerReady:
		if line != "winner-ready" {
			t.Fatalf("winner status = %q, stderr = %s", line, winnerStderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for winner to hold invocation lock")
	}

	var loserStdout, loserStderr bytes.Buffer
	loserCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	loser := exec.CommandContext(loserCtx, os.Args[0], "-test.run=^TestJanitorInvocationLockChild$")
	loser.Env = env
	loser.Stdout = &loserStdout
	loser.Stderr = &loserStderr
	if err := loser.Run(); err != nil {
		t.Fatalf("loser process: %v; stderr = %s", err, loserStderr.String())
	}
	loserLines := strings.Split(strings.TrimSpace(loserStdout.String()), "\n")
	if len(loserLines) == 0 || loserLines[0] != "loser" {
		t.Fatalf("loser status = %q, stderr = %s", strings.TrimSpace(loserStdout.String()), loserStderr.String())
	}

	actions, err := os.ReadFile(actionLog)
	if err != nil {
		t.Fatalf("read action log before release: %v", err)
	}
	if got, want := strings.TrimSpace(string(actions)), "migrate\nverify\nmas\nsmtp"; got != want {
		t.Fatalf("actions before releasing winner = %q, want only winner actions %q", got, want)
	}

	if err := winnerStdinWriter.Close(); err != nil {
		t.Fatalf("release winner: %v", err)
	}
	winnerErr := <-winnerDone
	winnerFinished = true
	if winnerErr != nil {
		t.Fatalf("winner process: %v; stderr = %s", winnerErr, winnerStderr.String())
	}
}

// TestJanitorInvocationLockChild is the subprocess body for the integration test above. It is a
// test function so the parent can launch the already-built test binary without building another
// executable or adding a production-only entry point.
func TestJanitorInvocationLockChild(t *testing.T) {
	if os.Getenv("JANITOR_INVOCATION_CHILD") != "1" {
		return
	}
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("TEST_DATABASE_URL is required in child")
	}
	ctx := context.Background()
	pool, err := OpenJanitorPool(ctx, dsn)
	if err != nil {
		t.Fatalf("child OpenJanitorPool: %v", err)
	}
	defer pool.Close()

	lock, err := AcquireJanitorInvocationLock(ctx, pool)
	if errors.Is(err, ErrJanitorAlreadyRunning) {
		fmt.Fprintln(os.Stdout, "loser")
		return
	}
	if err != nil {
		t.Fatalf("child AcquireJanitorInvocationLock: %v", err)
	}
	defer func() {
		if err := lock.Release(context.Background()); err != nil {
			t.Errorf("Release: %v", err)
		}
	}()

	actionLog := os.Getenv("JANITOR_ACTION_LOG")
	record := func(action string) {
		file, openErr := os.OpenFile(actionLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if openErr != nil {
			t.Fatalf("open action log: %v", openErr)
		}
		_, writeErr := fmt.Fprintln(file, action)
		closeErr := file.Close()
		if writeErr != nil {
			t.Fatalf("write action log: %v", writeErr)
		}
		if closeErr != nil {
			t.Fatalf("close action log: %v", closeErr)
		}
	}

	store := NewStore(pool)
	record("migrate")
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("child Migrate: %v", err)
	}
	record("verify")
	if err := store.VerifyDeploymentIdentity(ctx, "telecrypt.io", "live"); err != nil {
		t.Fatalf("child VerifyDeploymentIdentity: %v", err)
	}
	record("mas")
	record("smtp")

	if os.Getenv("JANITOR_CHILD_HOLD") != "1" {
		fmt.Fprintln(os.Stdout, "unexpected-winner")
		return
	}
	fmt.Fprintln(os.Stdout, "winner-ready")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("wait for winner release: %v", err)
	}
}
