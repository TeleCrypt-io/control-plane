// Package registrationhttp is Registration's public HTTP API: a stateless registration shim exposing only
// POST /agents. It holds no database connection, no admin credentials, no
// stored sessions, and no edge token; it drives MAS's public registration/device-OAuth flow and
// applies an in-memory rate limit.
package registrationhttp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/agent"
	"github.com/TeleCrypt-io/controlplane/internal/httpdiag"
	"github.com/TeleCrypt-io/controlplane/internal/registrationfailure"
)

// provisioner is the subset of *agent.Provisioner the server needs. Defined here so tests can
// supply a fake without driving a real MAS instance.
type provisioner interface {
	ProvisionAgent(ctx context.Context) (*agent.Provisioned, error)
}

type Server struct {
	provisioner provisioner
	rateLimiter *RateLimiter
	planURL     string
	mux         *http.ServeMux
}

const maxRegistrationBodyBytes = 4096

const registrationErrorHeader = "Telecrypt-Registration-Error"

func New(p provisioner, rl *RateLimiter, planURL string) *Server {
	s := &Server{
		provisioner: p,
		rateLimiter: rl,
		planURL:     planURL,
		mux:         http.NewServeMux(),
	}
	s.mux.HandleFunc("POST /agents", s.handleRegistration)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

type registrationResponse struct {
	MXID               string `json:"mxid"`
	Password           string `json:"password"`
	AccessToken        string `json:"access_token"`
	RefreshToken       string `json:"refresh_token"`
	ExpiresIn          int    `json:"expires_in"`
	DeviceID           string `json:"device_id"`
	Homeserver         string `json:"homeserver"`
	OAuthIssuer        string `json:"issuer"`
	OAuthClientID      string `json:"client_id"`
	OAuthTokenEndpoint string `json:"token_endpoint"`
	PlanURL            string `json:"plan_url"`
}

// handleRegistration provisions a fresh agent account through MAS's public registration and OAuth
// flow — no admin credential, password login, edge token, or database. Rate-limited by a global
// in-memory backstop; client-facing fairness belongs at the network boundary.
func (s *Server) handleRegistration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Del(registrationErrorHeader)
	if r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxRegistrationBodyBytes+1))
		if err != nil || len(body) != 0 {
			http.Error(w, "request body must be empty", http.StatusBadRequest)
			return
		}
	}
	allowed := s.rateLimiter.Allow()
	if !allowed {
		http.Error(w, "rate limit exceeded, try again later", http.StatusTooManyRequests)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	result, err := s.provisioner.ProvisionAgent(ctx)
	if err != nil {
		// The typed error retains a complete sanitized diagnostic for internal logs. Only its
		// finite code crosses the public boundary.
		code := registrationfailure.Code(err)
		w.Header().Set(registrationErrorHeader, code)
		slog.Error("registration: provisioning failed", "code", code, "error", httpdiag.Sanitize(err.Error()))
		http.Error(w, "provisioning failed", http.StatusInternalServerError)
		return
	}

	resp := registrationResponse{
		MXID:               result.MXID,
		Password:           result.Password,
		AccessToken:        result.AccessToken,
		RefreshToken:       result.RefreshToken,
		ExpiresIn:          result.ExpiresIn,
		DeviceID:           result.DeviceID,
		Homeserver:         result.Homeserver,
		OAuthIssuer:        result.OAuthIssuer,
		OAuthClientID:      result.OAuthClientID,
		OAuthTokenEndpoint: result.OAuthTokenEndpoint,
		PlanURL:            s.planURL,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("registration: failed to write response", "code", registrationfailure.Code(registrationfailure.WithKind(registrationfailure.StageInternal, registrationfailure.KindInternal, err)), "error", httpdiag.Sanitize(err.Error()))
	}
}
