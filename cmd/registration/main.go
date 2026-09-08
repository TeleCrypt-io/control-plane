// Command registration runs TeleCrypt.io's stateless agent-registration shim: POST /agents drives
// MAS's public registration and OAuth device flow (no admin credentials, database, or password
// login — see internal/agent and internal/masreg).
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

	"github.com/TeleCrypt-io/controlplane/internal/agent"
	"github.com/TeleCrypt-io/controlplane/internal/config"
	"github.com/TeleCrypt-io/controlplane/internal/httpdiag"
	"github.com/TeleCrypt-io/controlplane/internal/masreg"
	"github.com/TeleCrypt-io/controlplane/internal/registrationhttp"
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "error", httpdiag.Sanitize(err.Error()))
		return err
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	handler, err := build(cfg)
	if err != nil {
		slog.Error("startup", "error", httpdiag.Sanitize(err.Error()))
		return err
	}

	srv := &http.Server{
		Addr:              registrationListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      65 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	serverErrors := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", registrationListenAddr)
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
		return shutdownRegistrationAfterFailure(srv, err)
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

func shutdownRegistrationAfterFailure(server *http.Server, serveErr error) error {
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
		return errors.Join(errors.New("registration HTTP shutdown failed"), err)
	}
	return nil
}

func build(cfg *config.Config) (http.Handler, error) {
	if err := cfg.ValidateRegistration(); err != nil {
		return nil, err
	}

	// MAS registration and device OAuth use browser-visible public URLs because MAS builds
	// redirects and native-client metadata from its configured public base URL.
	masRegClient := masreg.NewClient(cfg.MASPublicURL)

	provisioner, err := agent.NewProvisioner(masRegClient, cfg.BackendPublicURL, cfg.ServerName)
	if err != nil {
		return nil, err
	}

	rateLimiter := registrationhttp.NewRateLimiter(
		registrationRateLimitGlobal, registrationRateLimitWindow)

	return registrationhttp.New(provisioner, rateLimiter, cfg.PlanPublicURL), nil
}

const (
	registrationListenAddr      = ":9009"
	registrationRateLimitGlobal = 60
	registrationRateLimitWindow = time.Minute
)
