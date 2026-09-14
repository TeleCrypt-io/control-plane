package registrationfailure

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "secret timeout text" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type transportError struct{}

func (transportError) Error() string   { return "secret transport text" }
func (transportError) Timeout() bool   { return false }
func (transportError) Temporary() bool { return false }

var _ net.Error = timeoutError{}
var _ net.Error = transportError{}

func TestClassifyUsesTypedPropertiesWithoutParsingText(t *testing.T) {
	secret := errors.New("provider=password&token=secret")
	for _, test := range []struct {
		name string
		err  error
		want Kind
	}{
		{name: "deadline", err: context.DeadlineExceeded, want: KindTimeout},
		{name: "cancelled", err: context.Canceled, want: KindCancelled},
		{name: "timeout", err: fmt.Errorf("wrapped: %w", timeoutError{}), want: KindTimeout},
		{name: "transport", err: fmt.Errorf("wrapped: %w", transportError{}), want: KindTransport},
		{name: "upstream", err: Upstream(secret), want: KindUpstream},
		{name: "protocol", err: Protocol(secret), want: KindProtocol},
		{name: "invariant", err: Invariant(secret), want: KindInvariant},
		{name: "unknown", err: secret, want: KindInternal},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := Classify(test.err); got != test.want {
				t.Fatalf("Classify() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestCodeCoversFiniteVocabularyAndHidesUnderlyingText(t *testing.T) {
	secret := errors.New("password=secret token=secret")
	stages := []Stage{
		StageLocalGeneration, StageRegistrationForm, StageRegistrationPassword,
		StageRegistrationDisplayName, StageOAuthClient, StageDeviceAuthorization,
		StageDeviceConsent, StageDeviceToken, StageIdentity, StageInternal,
	}
	kinds := []Kind{
		KindTimeout, KindCancelled, KindTransport, KindUpstream, KindProtocol,
		KindInvariant, KindInternal,
	}
	for _, stage := range stages {
		for _, kind := range kinds {
			got := Code(WithKind(stage, kind, secret))
			want := string(stage) + "/" + string(kind)
			if got != want {
				t.Fatalf("Code(%q, %q) = %q, want %q", stage, kind, got, want)
			}
			if errors.Is(WithKind(stage, kind, secret), secret) == false {
				t.Fatal("typed failure must retain underlying error for internal errors.Is checks")
			}
			if errors.Is(errors.New(got), secret) {
				t.Fatal("bounded code unexpectedly contains underlying secret")
			}
		}
	}
	if got := Code(secret); got != "internal/internal" {
		t.Fatalf("unknown error Code = %q, want internal/internal", got)
	}
	if got := Code(WithKind(Stage("bad"), Kind("bad"), secret)); got != "internal/internal" {
		t.Fatalf("invalid typed error Code = %q, want internal/internal", got)
	}
}

func TestCodePreservesStageThroughFormattedWrappers(t *testing.T) {
	wrapped := fmt.Errorf("operation context: %w", WithKind(StageDeviceConsent, KindProtocol, errors.New("provider response secret")))
	if got, want := Code(wrapped), "device_consent/protocol"; got != want {
		t.Fatalf("Code(wrapped failure) = %q, want %q", got, want)
	}
}

func TestErrorRetainsCompleteRawCauseWhileCodeStaysBounded(t *testing.T) {
	const secret = "access_token=secret-value"
	err := WithKind(StageDeviceToken, KindProtocol, errors.New(secret+" tail"))
	if got := err.Error(); !strings.Contains(got, secret+" tail") {
		t.Fatalf("typed error = %q, want complete raw cause", got)
	}
	if got, want := Code(err), "device_token/protocol"; got != want {
		t.Fatalf("Code() = %q, want bounded code %q", got, want)
	}
}
