package registrationhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/agent"
	"github.com/TeleCrypt-io/controlplane/internal/registrationfailure"
)

type fakeProvisioner struct {
	result *agent.Provisioned
	err    error
	calls  int
}

type contextProvisioner struct{ hasDeadline bool }

func (p *contextProvisioner) ProvisionAgent(ctx context.Context) (*agent.Provisioned, error) {
	_, p.hasDeadline = ctx.Deadline()
	return &agent.Provisioned{}, nil
}

func TestHandleRegistration_BoundsProvisioningTime(t *testing.T) {
	p := &contextProvisioner{}
	s := New(p, NewRateLimiter(60, time.Minute), "https://telecrypt.io/plan")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/agents", nil))
	if !p.hasDeadline {
		t.Fatal("ProvisionAgent did not receive a bounded context")
	}
}

func TestHandleRegistration_LogsSanitizedProvisioningError(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	secret := "password=generated-password-must-not-appear"
	s := New(&fakeProvisioner{err: registrationfailure.WithKind(registrationfailure.StageDeviceConsent, registrationfailure.KindUpstream, errors.New(secret+" tail"))}, NewRateLimiter(60, time.Minute), "https://telecrypt.io/plan")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/agents", nil))
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("provisioning log leaked secret: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "tail") {
		t.Fatalf("provisioning log omitted sanitized diagnostic: %s", logs.String())
	}
	if got, want := w.Header().Get(registrationErrorHeader), "device_consent/upstream"; got != want {
		t.Fatalf("registration error header = %q, want %q", got, want)
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Fatalf("provisioning response leaked secret: %s", w.Body.String())
	}
}

func (f *fakeProvisioner) ProvisionAgent(ctx context.Context) (*agent.Provisioned, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func TestHandleRegistration_HappyPath(t *testing.T) {
	p := &fakeProvisioner{result: &agent.Provisioned{
		MXID:               "@abc123:telecrypt.io",
		Password:           "generated-password",
		AccessToken:        "oauth-access",
		RefreshToken:       "oauth-refresh",
		ExpiresIn:          3600,
		DeviceID:           "AGTDEADBEEF",
		Homeserver:         "https://telecrypt.io",
		OAuthIssuer:        "https://telecrypt.io/auth",
		OAuthClientID:      "dynamic-client",
		OAuthTokenEndpoint: "https://telecrypt.io/auth/oauth2/token",
	}}
	s := New(p, NewRateLimiter(60, time.Minute), "https://backend.telecrypt.io/plan")

	req := httptest.NewRequest("POST", "/agents", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["mxid"] != "@abc123:telecrypt.io" {
		t.Errorf("mxid = %v, want @abc123:telecrypt.io", resp["mxid"])
	}
	if resp["password"] != "generated-password" || resp["access_token"] != "oauth-access" || resp["refresh_token"] != "oauth-refresh" || resp["expires_in"] != float64(3600) {
		t.Errorf("credential response = %v, want complete refreshable OAuth credentials", resp)
	}
	if resp["issuer"] != "https://telecrypt.io/auth" || resp["client_id"] != "dynamic-client" || resp["token_endpoint"] != "https://telecrypt.io/auth/oauth2/token" {
		t.Errorf("OAuth refresh metadata = %v", resp)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", w.Header().Get("Cache-Control"))
	}
	if got := w.Header().Get(registrationErrorHeader); got != "" {
		t.Fatalf("successful response has registration error header %q", got)
	}
	plan, ok := resp["plan_url"]
	if !ok {
		t.Fatal("response must contain plan_url — guidance for attaching to a paid plan")
	}
	if plan != "https://backend.telecrypt.io/plan" {
		t.Errorf("plan_url = %v, want https://backend.telecrypt.io/plan", plan)
	}
}

func TestHandleRegistration_RejectsNonEmptyBody(t *testing.T) {
	p := &fakeProvisioner{result: &agent.Provisioned{MXID: "@abc123:telecrypt.io"}}
	s := New(p, NewRateLimiter(60, time.Minute), "https://backend.telecrypt.io/plan")
	req := httptest.NewRequest("POST", "/agents", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("non-empty body status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if p.calls != 0 {
		t.Fatalf("provisioner calls = %d, want none for non-empty body", p.calls)
	}
}

func TestHandleRegistration_ProvisioningFails(t *testing.T) {
	p := &fakeProvisioner{err: registrationfailure.WithKind(registrationfailure.StageOAuthClient, registrationfailure.KindTransport, errors.New("mas unreachable"))}
	s := New(p, NewRateLimiter(60, time.Minute), "https://backend.telecrypt.io/plan")

	req := httptest.NewRequest("POST", "/agents", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != 500 {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", w.Header().Get("Cache-Control"))
	}
	if got, want := w.Header().Get(registrationErrorHeader), "oauth_client/transport"; got != want {
		t.Errorf("registration error header = %q, want %q", got, want)
	}
}

func TestHandleRegistration_RateLimited(t *testing.T) {
	p := &fakeProvisioner{result: &agent.Provisioned{MXID: "@x:telecrypt.io"}}
	s := New(p, NewRateLimiter(1, time.Minute), "https://telecrypt.io/plan")

	req1 := httptest.NewRequest("POST", "/agents", nil)
	w1 := httptest.NewRecorder()
	s.ServeHTTP(w1, req1)
	if w1.Code != 200 {
		t.Fatalf("first call: status = %d, want 200", w1.Code)
	}

	req2 := httptest.NewRequest("POST", "/agents", nil)
	w2 := httptest.NewRecorder()
	s.ServeHTTP(w2, req2)
	if w2.Code != 429 {
		t.Errorf("second global call: status = %d, want 429", w2.Code)
	}
	if got := w2.Header().Get(registrationErrorHeader); got != "" {
		t.Errorf("rate-limited response has registration error header %q", got)
	}
	if p.calls != 1 {
		t.Errorf("provisioner should not be called once rate-limited, calls = %d", p.calls)
	}
}

func TestHandleRegistration_MapsEveryBoundedStageAndKind(t *testing.T) {
	stages := []registrationfailure.Stage{
		registrationfailure.StageLocalGeneration,
		registrationfailure.StageRegistrationForm,
		registrationfailure.StageRegistrationPassword,
		registrationfailure.StageRegistrationDisplayName,
		registrationfailure.StageOAuthClient,
		registrationfailure.StageDeviceAuthorization,
		registrationfailure.StageDeviceConsent,
		registrationfailure.StageDeviceToken,
		registrationfailure.StageIdentity,
		registrationfailure.StageInternal,
	}
	kinds := []registrationfailure.Kind{
		registrationfailure.KindTimeout,
		registrationfailure.KindCancelled,
		registrationfailure.KindTransport,
		registrationfailure.KindUpstream,
		registrationfailure.KindProtocol,
		registrationfailure.KindInvariant,
		registrationfailure.KindInternal,
	}
	for _, stage := range stages {
		for _, kind := range kinds {
			t.Run(string(stage)+"/"+string(kind), func(t *testing.T) {
				const secret = "credential=must-not-escape"
				p := &fakeProvisioner{err: registrationfailure.WithKind(stage, kind, errors.New(secret))}
				s := New(p, NewRateLimiter(60, time.Minute), "https://telecrypt.io/plan")
				w := httptest.NewRecorder()
				s.ServeHTTP(w, httptest.NewRequest("POST", "/agents", nil))
				want := string(stage) + "/" + string(kind)
				if w.Code != http.StatusInternalServerError || w.Header().Get(registrationErrorHeader) != want {
					t.Fatalf("response = %d, header %q, want 500/%q", w.Code, w.Header().Get(registrationErrorHeader), want)
				}
				if strings.Contains(w.Body.String(), secret) {
					t.Fatalf("response leaked secret: %s", w.Body.String())
				}
			})
		}
	}
}
