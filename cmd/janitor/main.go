// Command janitor is TeleCrypt.io's one-shot maintenance process holding a standing MAS admin
// credential. Each invocation locks stale unclaimed agent accounts via MAS's admin API and, when
// configured, emails the owner a digest of new human sign-ups awaiting review.
//
// Janitor is a one-shot process and opens no listening network port.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/TeleCrypt-io/controlplane/internal/config"
	"github.com/TeleCrypt-io/controlplane/internal/db"
	"github.com/TeleCrypt-io/controlplane/internal/httpdiag"
	"github.com/TeleCrypt-io/controlplane/internal/janitor"
	"github.com/TeleCrypt-io/controlplane/internal/masadmin"
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() (runErr error) {
	cfg, err := config.LoadJanitor()
	if err != nil {
		slog.Error("config", "error", httpdiag.Sanitize(err.Error()))
		return err
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx := signalCtx

	pool, err := db.OpenJanitorPool(ctx, cfg.JanitorDBURL)
	if err != nil {
		slog.Error("db connect", "error", httpdiag.Sanitize(err.Error()))
		return err
	}
	defer pool.Close()
	if err := db.ValidateJanitorRole(ctx, pool); err != nil {
		slog.Error("db role", "error", httpdiag.Sanitize(err.Error()))
		return err
	}
	invocationLock, err := db.AcquireJanitorInvocationLock(ctx, pool)
	if err != nil {
		slog.Error("janitor single-flight", "error", httpdiag.Sanitize(err.Error()))
		return err
	}
	defer func() {
		if releaseErr := invocationLock.Release(ctx); releaseErr != nil {
			slog.Error("janitor invocation-lock release", "error", httpdiag.Sanitize(releaseErr.Error()))
			runErr = errors.Join(runErr, releaseErr)
		}
	}()

	if err := db.ValidateJanitorSchemaACL(ctx, pool); err != nil {
		slog.Error("db schema contract", "error", httpdiag.Sanitize(err.Error()))
		return err
	}
	store := db.NewStore(pool)
	if err := db.Migrate(ctx, pool); err != nil {
		slog.Error("migrate", "error", httpdiag.Sanitize(err.Error()))
		return err
	}
	if err := store.VerifyDeploymentIdentity(ctx, cfg.ServerName, cfg.BillingEnvironment); err != nil {
		slog.Error("deployment identity", "error", httpdiag.Sanitize(err.Error()))
		return err
	}
	if err := db.ValidateJanitorDatabaseContract(ctx, pool, cfg.CashierDBRole); err != nil {
		slog.Error("db contract", "error", httpdiag.Sanitize(err.Error()))
		return err
	}

	sweeper := build(cfg, store)

	if err := sweeper.Sweep(ctx); err != nil {
		slog.Error("sweep", "error", httpdiag.Sanitize(err.Error()))
		return err
	}
	slog.Info("janitor sweep complete")
	return nil
}

func build(cfg *config.JanitorConfig, store *db.Store) *janitor.Sweeper {
	masClient := masadmin.NewClient(cfg.MASAdminURL, cfg.MASAdminClientID, cfg.MASAdminClientSecret)
	mailer := &janitor.SMTPMailer{
		Host:     cfg.SMTPHost,
		Port:     janitorSMTPPort,
		Username: cfg.SMTPUsername,
		Password: cfg.SMTPPassword,
		From:     cfg.SMTPFrom,
	}

	return janitor.NewSweeper(masClient, store, mailer, janitor.Config{
		ServerName: cfg.ServerName, BillingEnvironment: cfg.BillingEnvironment,
		OwnerEmail: cfg.OwnerEmail,
	})
}

const (
	janitorSMTPPort = "587"
)
