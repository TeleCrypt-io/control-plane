// Package registrationhttp is Registration's public HTTP API: a stateless registration shim exposing only
// POST /redpill. It holds no database connection, no admin credentials, no
// stored sessions, and no edge token; it drives MAS's public registration/device-OAuth flow.
package registrationhttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/agent"
	"github.com/TeleCrypt-io/controlplane/internal/registrationfailure"
)

// provisioner is the subset of *agent.Provisioner the server needs. Defined here so tests can
// supply a fake without driving a real MAS instance.
type provisioner interface {
	ProvisionAgent(ctx context.Context) (*agent.Provisioned, error)
}

type Server struct {
	provisioner provisioner
	planURL     string
	mux         *http.ServeMux
}

const registrationErrorHeader = "Telecrypt-Registration-Error"

// Keep provisioning below the registration server's 65-second write timeout so a stalled
// upstream cannot hold a request until the server forcibly closes the connection.
const provisioningTimeout = 60 * time.Second

func New(p provisioner, planURL string) *Server {
	s := &Server{
		provisioner: p,
		planURL:     planURL,
		mux:         http.NewServeMux(),
	}
	s.mux.HandleFunc("POST /redpill", s.handleRegistration)
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
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
// flow — no admin credential, password login, edge token, or database.
func (s *Server) handleRegistration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Del(registrationErrorHeader)
	if r.Body != nil {
		n, err := io.CopyN(io.Discard, r.Body, 1)
		if (err != nil && !errors.Is(err, io.EOF)) || n != 0 {
			http.Error(w, "request body must be empty", http.StatusBadRequest)
			return
		}
	}
	provisioningCtx, cancel := context.WithTimeout(r.Context(), provisioningTimeout)
	defer cancel()
	result, err := s.provisioner.ProvisionAgent(provisioningCtx)
	if err != nil {
		// Only the finite code and generic message cross the public boundary; the complete error
		// is retained in internal logs.
		code := registrationfailure.Code(err)
		w.Header().Set(registrationErrorHeader, code)
		slog.Error("registration: provisioning failed", "code", code, "error", err.Error())
		status := http.StatusInternalServerError
		if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		http.Error(w, "provisioning failed", status)
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
		slog.Error("registration: failed to write response", "code", registrationfailure.Code(registrationfailure.WithKind(registrationfailure.StageInternal, registrationfailure.KindInternal, err)), "error", err.Error())
	}
}
