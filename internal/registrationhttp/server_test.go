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
	"testing/synctest"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/agent"
	"github.com/TeleCrypt-io/controlplane/internal/registrationfailure"
)

type fakeProvisioner struct {
	result              *agent.Provisioned
	err                 error
	calls               int
	ctx                 context.Context
	waitForCancellation bool
}

func TestHandleRegistrationLogsRawErrorAndReturnsGenericResponse(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	secret := "password=generated-password-must-not-appear"
	s := New(&fakeProvisioner{err: registrationfailure.WithKind(registrationfailure.StageDeviceConsent, registrationfailure.KindUpstream, errors.New(secret+" tail"))}, "https://telecrypt.io/plan/overview")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/redpill", nil))
	if !strings.Contains(logs.String(), secret+" tail") {
		t.Fatalf("provisioning log omitted complete raw diagnostic: %s", logs.String())
	}
	if got, want := w.Header().Get(registrationErrorHeader), "device_consent/upstream"; got != want {
		t.Fatalf("registration error header = %q, want %q", got, want)
	}
	if got, want := w.Body.String(), "provisioning failed\n"; got != want {
		t.Fatalf("provisioning response = %q, want generic response %q", got, want)
	}
}

func (f *fakeProvisioner) ProvisionAgent(ctx context.Context) (*agent.Provisioned, error) {
	f.ctx = ctx
	f.calls++
	if f.waitForCancellation {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func TestHandleRegistrationBoundsProvisioningAndMapsDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &fakeProvisioner{waitForCancellation: true}
		s := New(p, "https://telecrypt.io/plan/overview")
		w := httptest.NewRecorder()
		started := time.Now()
		s.ServeHTTP(w, httptest.NewRequest("POST", "/redpill", nil))

		if p.ctx == nil {
			t.Fatal("provisioner did not receive a context")
		}
		deadline, ok := p.ctx.Deadline()
		if !ok {
			t.Fatal("provisioning context has no deadline")
		}
		if got := deadline.Sub(started); got != provisioningTimeout {
			t.Fatalf("provisioning deadline window = %s, want %s", got, provisioningTimeout)
		}
		if got := time.Since(started); got != provisioningTimeout {
			t.Fatalf("provisioning elapsed = %s, want %s", got, provisioningTimeout)
		}
		if p.calls != 1 {
			t.Fatalf("provisioner calls = %d, want one bounded attempt", p.calls)
		}
		if w.Code != http.StatusGatewayTimeout {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusGatewayTimeout)
		}
		if strings.Contains(w.Body.String(), "deadline") {
			t.Fatalf("timeout response leaked internal detail: %s", w.Body.String())
		}
	})
}

func TestHandleRegistrationRetainsCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := &fakeProvisioner{waitForCancellation: true}
	s := New(p, "https://telecrypt.io/plan/overview")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/redpill", nil).WithContext(ctx))

	if p.calls != 1 || p.ctx == nil || !errors.Is(p.ctx.Err(), context.Canceled) {
		t.Fatalf("caller cancellation = calls %d, context error %v; want one canceled provisioning call", p.calls, p.ctx.Err())
	}
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d for caller cancellation", w.Code, http.StatusInternalServerError)
	}
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
		OAuthIssuer:        "https://telecrypt.io/",
		OAuthClientID:      "dynamic-client",
		OAuthTokenEndpoint: "https://telecrypt.io/oauth2/token",
	}}
	s := New(p, "https://backend.telecrypt.io/plan/overview")

	req := httptest.NewRequest("POST", "/redpill", nil)
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
	if resp["issuer"] != "https://telecrypt.io/" || resp["client_id"] != "dynamic-client" || resp["token_endpoint"] != "https://telecrypt.io/oauth2/token" {
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
	if plan != "https://backend.telecrypt.io/plan/overview" {
		t.Errorf("plan_url = %v, want https://backend.telecrypt.io/plan/overview", plan)
	}
}

func TestHandleRegistration_RejectsNonEmptyBody(t *testing.T) {
	p := &fakeProvisioner{result: &agent.Provisioned{MXID: "@abc123:telecrypt.io"}}
	s := New(p, "https://backend.telecrypt.io/plan/overview")
	req := httptest.NewRequest("POST", "/redpill", strings.NewReader("{}"))
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
	s := New(p, "https://backend.telecrypt.io/plan/overview")

	req := httptest.NewRequest("POST", "/redpill", nil)
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
				s := New(p, "https://telecrypt.io/plan/overview")
				w := httptest.NewRecorder()
				s.ServeHTTP(w, httptest.NewRequest("POST", "/redpill", nil))
				want := string(stage) + "/" + string(kind)
				if w.Code != http.StatusInternalServerError || w.Header().Get(registrationErrorHeader) != want {
					t.Fatalf("response = %d, header %q, want 500/%q", w.Code, w.Header().Get(registrationErrorHeader), want)
				}
				if strings.Contains(w.Body.String(), secret) {
					t.Fatalf("public response contained internal detail: %s", w.Body.String())
				}
			})
		}
	}
}

// Probing health must not create an account or call billing services.
func TestInternalHealth(t *testing.T) {
	srv := New(nil, "")
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/internal/registration_health", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", response.Code)
	}
}
