// Package jsonbody decodes one JSON value from an upstream response.
package jsonbody

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/TeleCrypt-io/controlplane/internal/httpdiag"
)

var (
	// ErrTrailingData means the response contained more than one JSON value or
	// non-whitespace data after the first value.
	ErrTrailingData = errors.New("JSON body contains trailing data")
)

// DecodeError retains the complete sanitized response input and the underlying read or JSON
// error. Body is never truncated; callers choose the redactions for values they already know
// must not appear in diagnostics.
type DecodeError struct {
	Body      string
	cause     error
	causeText string
}

func (e *DecodeError) Error() string {
	parts := []string{"decode JSON body"}
	if e.Body != "" {
		parts = append(parts, "body="+strconv.Quote(e.Body))
	}
	if e.causeText != "" {
		parts = append(parts, "cause="+e.causeText)
	}
	return strings.Join(parts, ": ")
}

func (e *DecodeError) Unwrap() error { return e.cause }

func newDecodeError(body []byte, cause error, redactions ...string) error {
	return &DecodeError{
		Body:      httpdiag.Sanitize(string(body), redactions...),
		cause:     cause,
		causeText: httpdiag.Sanitize(cause.Error(), redactions...),
	}
}

// Decode reads the complete response, decodes exactly one JSON value into dst,
// and rejects any trailing JSON or data.
func Decode(r io.Reader, dst any, redactions ...string) error {
	body, err := io.ReadAll(r)
	if err != nil {
		return newDecodeError(body, err, redactions...)
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(dst); err != nil {
		return newDecodeError(body, err, redactions...)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return newDecodeError(body, ErrTrailingData, redactions...)
		}
		return newDecodeError(body, fmt.Errorf("%w: %v", ErrTrailingData, err), redactions...)
	}
	return nil
}
