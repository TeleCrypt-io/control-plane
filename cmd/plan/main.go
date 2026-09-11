// Command plan is TeleCrypt's public account, plan, and subscription-management service.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/config"
	"github.com/TeleCrypt-io/controlplane/internal/httpdiag"
	"github.com/TeleCrypt-io/controlplane/internal/masadmin"
	"github.com/TeleCrypt-io/controlplane/internal/plan"
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadPlan()
	if err != nil {
		slog.Error("config", "error", httpdiag.Sanitize(err.Error()))
		return err
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cashierClient, err := plan.NewHTTPCashierClient(cfg.CashierInternalURL, cfg.PlanAssertionPrivateKey, nil)
	if err != nil {
		slog.Error("cashier client", "error", httpdiag.Sanitize(err.Error()))
		return err
	}

	srv := &http.Server{
		Addr: planListenAddr,
		Handler: plan.NewServer(plan.Config{
			BillingEnvironment: cfg.BillingEnvironment,
			ServerName:         cfg.ServerName,
			BackendPublicURL:   cfg.BackendPublicURL,
			MASInternalURL:     cfg.MASInternalURL,
			PlanPublicURL:      cfg.PlanPublicURL,
			MASClientID:        cfg.MASClientID,
			MASClientSecret:    cfg.MASClientSecret,
			PlanSessionKey:     cfg.PlanSessionKey,
		}, cashierClient, masadmin.NewClient(cfg.MASAdminURL, cfg.MASAdminClientID, cfg.MASAdminClientSecret)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	serverErrors := make(chan error, 1)
	go func() {
		slog.Info("plan listening", "addr", planListenAddr)
		serverErrors <- srv.ListenAndServe()
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-serverErrors:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		slog.Error("server", "error", httpdiag.Sanitize(err.Error()))
		stop()
		return shutdownPlanAfterFailure(srv, err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := shutdownHTTPServer(shutdownCtx, srv); err != nil {
			slog.Error("shutdown", "error", httpdiag.Sanitize(err.Error()))
			return err
		}
		return nil
	}
}

func shutdownPlanAfterFailure(server *http.Server, serveErr error) error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := shutdownHTTPServer(shutdownCtx, server); err != nil {
		slog.Error("shutdown", "error", httpdiag.Sanitize(err.Error()))
		return errors.Join(serveErr, err)
	}
	return serveErr
}

func shutdownHTTPServer(ctx context.Context, server *http.Server) error {
	if err := server.Shutdown(ctx); err != nil {
		return errors.Join(errors.New("Plan HTTP shutdown failed"), err)
	}
	return nil
}

const planListenAddr = ":9012"
