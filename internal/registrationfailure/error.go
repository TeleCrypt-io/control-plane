// Package registrationfailure defines the one bounded failure vocabulary shared by the
// registration flow and its HTTP boundary. Its Error text retains the complete sanitized
// underlying diagnostic for internal logs and callers may unwrap it for control flow. External
// responses use only Code.
package registrationfailure

import (
	"context"
	"errors"
	"net"

	"github.com/TeleCrypt-io/controlplane/internal/httpdiag"
)

type Stage string

const (
	StageLocalGeneration         Stage = "local_generation"
	StageRegistrationForm        Stage = "registration_form"
	StageRegistrationPassword    Stage = "registration_password"
	StageRegistrationDisplayName Stage = "registration_display_name"
	StageOAuthClient             Stage = "oauth_client"
	StageDeviceAuthorization     Stage = "device_authorization"
	StageDeviceConsent           Stage = "device_consent"
	StageDeviceToken             Stage = "device_token"
	StageIdentity                Stage = "identity"
	StageInternal                Stage = "internal"
)

type Kind string

const (
	KindTimeout   Kind = "timeout"
	KindCancelled Kind = "cancelled"
	KindTransport Kind = "transport"
	KindUpstream  Kind = "upstream"
	KindProtocol  Kind = "protocol"
	KindInvariant Kind = "invariant"
	KindInternal  Kind = "internal"
)

// Error is the internal typed registration failure. Stage and Kind are finite values; all
// unrecognised or untyped failures intentionally collapse to internal/internal at the boundary.
type Error struct {
	Stage Stage
	Kind  Kind
	err   error
}

func (e *Error) Error() string {
	if e == nil || !valid(e.Stage, e.Kind) {
		return string(StageInternal) + "/" + string(KindInternal)
	}
	code := boundedCode(e.Stage, e.Kind)
	if e.err == nil {
		return code
	}
	detail := httpdiag.Sanitize(e.err.Error())
	if detail == "" {
		return code
	}
	return code + ": " + detail
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

// Wrap associates a stage with an error and classifies it without inspecting its text.
func Wrap(stage Stage, err error) error {
	if err == nil {
		return nil
	}
	var existing *Error
	if errors.As(err, &existing) && existing != nil && valid(existing.Stage, existing.Kind) {
		return err
	}
	return &Error{Stage: stage, Kind: Classify(err), err: err}
}

func WithKind(stage Stage, kind Kind, err error) error {
	if err == nil {
		return nil
	}
	if !valid(stage, kind) {
		return &Error{Stage: StageInternal, Kind: KindInternal, err: err}
	}
	return &Error{Stage: stage, Kind: kind, err: err}
}

// Protocol, Invariant, Upstream and Transport mark typed failures at their source. Their Error
// text retains a complete sanitized cause for internal diagnostics; callers crossing the HTTP
// boundary must use Code instead.
func Protocol(err error) error {
	if err == nil {
		return nil
	}
	return marked{kind: KindProtocol, err: err}
}

func Invariant(err error) error {
	if err == nil {
		return nil
	}
	return marked{kind: KindInvariant, err: err}
}

func Upstream(err error) error {
	if err == nil {
		return nil
	}
	return marked{kind: KindUpstream, err: err}
}

func Transport(err error) error {
	if err == nil {
		return nil
	}
	return marked{kind: KindTransport, err: err}
}

type marked struct {
	kind Kind
	err  error
}

func (e marked) Error() string {
	if e.err == nil {
		return string(e.kind)
	}
	detail := httpdiag.Sanitize(e.err.Error())
	if detail == "" {
		return string(e.kind)
	}
	return string(e.kind) + ": " + detail
}
func (e marked) Unwrap() error { return e.err }

// Classify maps only typed/context/network properties. It never parses error strings.
func Classify(err error) Kind {
	if err == nil {
		return KindInternal
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return KindTimeout
	}
	if errors.Is(err, context.Canceled) {
		return KindCancelled
	}
	var markedErr interface{ registrationFailureKind() Kind }
	if errors.As(err, &markedErr) {
		return markedErr.registrationFailureKind()
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return KindTimeout
	}
	var network net.Error
	if errors.As(err, &network) {
		return KindTransport
	}
	return KindInternal
}

// Code returns the bounded external code. Unknown, malformed, or absent typed errors map to the
// loud fail-closed value rather than exposing an implementation detail.
func Code(err error) string {
	var typed *Error
	if !errors.As(err, &typed) || typed == nil || !valid(typed.Stage, typed.Kind) {
		return string(StageInternal) + "/" + string(KindInternal)
	}
	return boundedCode(typed.Stage, typed.Kind)
}

func boundedCode(stage Stage, kind Kind) string {
	return string(stage) + "/" + string(kind)
}

func valid(stage Stage, kind Kind) bool {
	return validStage(stage) && validKind(kind)
}

func validStage(stage Stage) bool {
	switch stage {
	case StageLocalGeneration, StageRegistrationForm, StageRegistrationPassword,
		StageRegistrationDisplayName, StageOAuthClient, StageDeviceAuthorization,
		StageDeviceConsent, StageDeviceToken, StageIdentity, StageInternal:
		return true
	default:
		return false
	}
}

func validKind(kind Kind) bool {
	switch kind {
	case KindTimeout, KindCancelled, KindTransport, KindUpstream, KindProtocol, KindInvariant, KindInternal:
		return true
	default:
		return false
	}
}

func (e marked) registrationFailureKind() Kind { return e.kind }
