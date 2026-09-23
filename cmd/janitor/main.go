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

	sweeper := build(cfg)

	if err := sweeper.Sweep(ctx); err != nil {
		slog.Error("sweep", "error", err.Error())
		return err
	}
	slog.Info("janitor sweep complete")
	return nil
}

func build(cfg *config.JanitorConfig) *janitor.Sweeper {
	masClient := masadmin.NewClient(cfg.MASAdminURL, cfg.MASAdminClientID, cfg.MASAdminClientSecret)
	synapseClient := synapseadmin.NewClient(cfg.SynapseAdminURL, cfg.SynapseAdminToken)
	cashierClient := janitor.NewCashierClient(cfg.CashierToken)
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

	return janitor.NewLifecycleSweeper(masClient, synapseClient, cashierClient, mailer, dodoReader, janitor.Config{
		ServerName: cfg.ServerName, OperatorEmail: cfg.OperatorEmail,
	})
}

const (
	janitorSMTPPort = "587"
)
