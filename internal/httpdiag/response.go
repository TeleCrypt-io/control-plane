// Package httpdiag preserves complete, sanitized upstream HTTP diagnostics for internal
// callers. It never limits a diagnostic body: the caller owns the lifetime of the response and
// decides whether a body is diagnostic or merely an irrelevant keep-alive drain.
package httpdiag

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

var (
	credentialFieldPattern = regexp.MustCompile(`(?i)(["']?(access[_-]?token|refresh[_-]?token|token|client[_-]?secret|secret|api[_-]?key|password|authorization|cookie|set-cookie|csrf|device[_-]?(code|id)|user[_-]?(code|id)|username|email|mxid|client[_-]?id)["']?\s*[:=]\s*)("(\\.|[^"\\])*"|'[^']*'|[^\s,;}\]]+)`)
	bearerPattern         = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9+/=_\-.]+`)
	urlCredentialPattern  = regexp.MustCompile(`(?i)(://[^/\s:@]+:)[^@\s/]+(@)`)
	emailPattern           = regexp.MustCompile(`[A-Za-z0-9.!#$%&'*+/=?^_` + "{|}~" + `-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	matrixIDPattern        = regexp.MustCompile(`@[A-Za-z0-9._=+\-/]+:[A-Za-z0-9.-]+`)
	ulidPattern            = regexp.MustCompile(`\b[0-7][0-9A-HJKMNP-TV-Z]{25}\b`)
)

// ReadBody reads the complete body and returns its sanitized diagnostic text. A partial body is
// retained when the reader fails, and the read cause is returned separately.
func ReadBody(body io.Reader, redactions ...string) (string, error) {
	data, err := io.ReadAll(body)
	return Sanitize(string(data), redactions...), err
}

// ReadAndCloseBytes is the raw counterpart to ReadAndClose for callers that must decode a
// successful body after reading it while also retaining a sanitized copy for diagnostics. The
// caller must sanitize the returned bytes before putting them in an error.
func ReadAndCloseBytes(body io.ReadCloser) (data []byte, readErr, closeErr error) {
	data, readErr = io.ReadAll(body)
	closeErr = body.Close()
	return data, readErr, closeErr
}

// ReadAndClose reads the complete diagnostic body and always attempts to close it. Both causes
// remain available to the caller, including when the read fails before EOF.
func ReadAndClose(body io.ReadCloser, redactions ...string) (text string, readErr, closeErr error) {
	data, readErr, closeErr := ReadAndCloseBytes(body)
	text = Sanitize(string(data), redactions...)
	return text, readErr, closeErr
}

// DrainAndClose is only for successful or explicitly irrelevant response bodies whose contents
// are not diagnostics. io.Discard is intentional here: the body is consumed solely so the HTTP
// transport can reuse the connection, while all drain and close failures remain visible.
func DrainAndClose(body io.ReadCloser) (readErr, closeErr error) {
	_, readErr = io.Copy(io.Discard, body)
	closeErr = body.Close()
	return readErr, closeErr
}

// WrapCause keeps errors.Is/error.As behavior while exposing only sanitized cause text through
// Error. This prevents an upstream reader or closer from putting credentials or customer data
// into an internal error that later crosses a public boundary accidentally.
func WrapCause(label string, cause error, redactions ...string) error {
	if cause == nil {
		return nil
	}
	return &causeError{label: label, detail: Sanitize(cause.Error(), redactions...), cause: cause}
}

type causeError struct {
	label  string
	detail string
	cause  error
}

func (e *causeError) Error() string {
	if e.detail == "" {
		return e.label
	}
	return e.label + ": " + e.detail
}

func (e *causeError) Unwrap() error { return e.cause }

// ResponseError is a complete, sanitized upstream response diagnostic. Read and close causes are
// retained privately for errors.Is/error.As; Error uses the sanitized Body and cause details only.
type ResponseError struct {
	Operation  string
	StatusCode int
	Body       string

	readErr    error
	closeErr   error
	readCause  error
	closeCause error
}

// NewResponseError constructs a diagnostic without imposing a body-size limit. The supplied body
// is sanitized again so callers can safely pass either raw or already-sanitized text.
func NewResponseError(operation string, statusCode int, body string, readErr, closeErr error, redactions ...string) error {
	readCause := WrapCause("read response body", readErr, redactions...)
	closeCause := WrapCause("close response body", closeErr, redactions...)
	return &ResponseError{
		Operation:  operation,
		StatusCode: statusCode,
		Body:       Sanitize(body, redactions...),
		readErr:    readErr,
		closeErr:   closeErr,
		readCause:  readCause,
		closeCause: closeCause,
	}
}

func (e *ResponseError) Error() string {
	parts := []string{e.Operation, fmt.Sprintf("status %d", e.StatusCode)}
	if e.Body != "" {
		parts = append(parts, "body="+strconv.Quote(e.Body))
	}
	if e.readCause != nil {
		parts = append(parts, e.readCause.Error())
	}
	if e.closeCause != nil {
		parts = append(parts, e.closeCause.Error())
	}
	return strings.Join(parts, ": ")
}

func (e *ResponseError) Unwrap() error {
	return errors.Join(e.readErr, e.closeErr)
}

// Sanitize replaces caller-known secrets and identities, then removes common credential and
// customer-identity fields/patterns from otherwise untrusted upstream text. It preserves every
// non-sensitive byte in the diagnostic and never truncates it.
func Sanitize(value string, redactions ...string) string {
	for _, redaction := range redactions {
		if redaction != "" {
			value = strings.ReplaceAll(value, redaction, "[REDACTED]")
		}
	}
	value = bearerPattern.ReplaceAllString(value, `$1 [REDACTED]`)
	value = credentialFieldPattern.ReplaceAllString(value, `$1[REDACTED]`)
	value = urlCredentialPattern.ReplaceAllString(value, `$1[REDACTED]$2`)
	value = emailPattern.ReplaceAllString(value, "[CUSTOMER_EMAIL]")
	value = matrixIDPattern.ReplaceAllString(value, "[CUSTOMER_MXID]")
	return ulidPattern.ReplaceAllString(value, "[CUSTOMER_ID]")
}
