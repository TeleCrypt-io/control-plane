// Command janitor is TeleCrypt.io's one-shot lifecycle process. Each invocation uses its standing
// MAS and Synapse admin credentials for the agreed account-maintenance operation and, when
// configured, performs one read-only Dodo reconciliation and emails discrepancies.
//
// Janitor is a one-shot process and opens no listening network port.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/TeleCrypt-io/controlplane/internal/config"
	"github.com/TeleCrypt-io/controlplane/internal/db"
	"github.com/TeleCrypt-io/controlplane/internal/janitor"
	"github.com/TeleCrypt-io/controlplane/internal/masadmin"
	"github.com/TeleCrypt-io/controlplane/internal/synapseadmin"
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadJanitor()
	if err != nil {
		slog.Error("config", "error", err.Error())
		return err
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx := signalCtx

	pool, err := db.OpenJanitorPool(ctx, cfg.JanitorDBURL)
	if err != nil {
		slog.Error("db connect", "error", err.Error())
		return err
	}
	defer pool.Close()
	store := db.NewStore(pool)
	if err := db.Migrate(ctx, pool); err != nil {
		slog.Error("migrate", "error", err.Error())
		return err
	}

	sweeper := build(cfg, store)

	if err := sweeper.Sweep(ctx); err != nil {
		slog.Error("sweep", "error", err.Error())
		return err
	}
	slog.Info("janitor sweep complete")
	return nil
}

func build(cfg *config.JanitorConfig, store *db.Store) *janitor.Sweeper {
	masClient := masadmin.NewClient(cfg.MASAdminURL, cfg.MASAdminClientID, cfg.MASAdminClientSecret)
	synapseClient := synapseadmin.NewClient(cfg.SynapseAdminURL, cfg.SynapseAdminToken)
	var dodoReader janitor.DodoReconciler
	if cfg.DodoReadOnlyAPIURL != "" {
		dodoReader = janitor.NewDodoReader(cfg.DodoReadOnlyAPIURL, cfg.DodoReadOnlyAPIKey)
	}
	mailer := &janitor.SMTPMailer{
		Host:     cfg.SMTPHost,
		Port:     janitorSMTPPort,
		Username: cfg.SMTPUsername,
		Password: cfg.SMTPPassword,
		From:     cfg.SMTPFrom,
	}

	return janitor.NewLifecycleSweeper(masClient, synapseClient, store, mailer, dodoReader, janitor.Config{
		ServerName: cfg.ServerName, BillingEnvironment: cfg.BillingEnvironment,
		OwnerEmail: cfg.OwnerEmail,
	})
}

const (
	janitorSMTPPort = "587"
)
