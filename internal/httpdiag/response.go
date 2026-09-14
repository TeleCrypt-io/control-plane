// Package httpdiag keeps complete upstream HTTP response diagnostics for internal callers.
package httpdiag

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ReadBody reads the complete body. A partial body is retained when the reader fails, and the
// read cause is returned separately.
func ReadBody(body io.Reader) (string, error) {
	data, err := io.ReadAll(body)
	return string(data), err
}

// ReadAndCloseBytes reads the complete body and always attempts to close it.
func ReadAndCloseBytes(body io.ReadCloser) (data []byte, readErr, closeErr error) {
	data, readErr = io.ReadAll(body)
	closeErr = body.Close()
	return data, readErr, closeErr
}

// ReadAndClose reads the complete body and always attempts to close it.
func ReadAndClose(body io.ReadCloser) (text string, readErr, closeErr error) {
	data, readErr, closeErr := ReadAndCloseBytes(body)
	return string(data), readErr, closeErr
}

// DrainAndClose is for successful or otherwise irrelevant response bodies whose contents are not
// diagnostics. The body is consumed so the HTTP transport can reuse the connection.
func DrainAndClose(body io.ReadCloser) (readErr, closeErr error) {
	_, readErr = io.Copy(io.Discard, body)
	closeErr = body.Close()
	return readErr, closeErr
}

// WrapCause adds operation context while preserving errors.Is and errors.As behavior.
func WrapCause(label string, cause error) error {
	if cause == nil {
		return nil
	}
	return &causeError{label: label, cause: cause}
}

type causeError struct {
	label string
	cause error
}

func (e *causeError) Error() string {
	detail := e.cause.Error()
	if detail == "" {
		return e.label
	}
	return e.label + ": " + detail
}

func (e *causeError) Unwrap() error { return e.cause }

// ResponseError retains the complete upstream response body and body read/close errors.
type ResponseError struct {
	Operation  string
	StatusCode int
	Body       string

	readErr  error
	closeErr error
}

// NewResponseError constructs a diagnostic without imposing a body-size limit.
func NewResponseError(operation string, statusCode int, body string, readErr, closeErr error) error {
	return &ResponseError{
		Operation:  operation,
		StatusCode: statusCode,
		Body:       body,
		readErr:    readErr,
		closeErr:   closeErr,
	}
}

func (e *ResponseError) Error() string {
	parts := []string{e.Operation, fmt.Sprintf("status %d", e.StatusCode)}
	if e.Body != "" {
		parts = append(parts, "body="+strconv.Quote(e.Body))
	}
	if e.readErr != nil {
		parts = append(parts, "read response body: "+e.readErr.Error())
	}
	if e.closeErr != nil {
		parts = append(parts, "close response body: "+e.closeErr.Error())
	}
	return strings.Join(parts, ": ")
}

func (e *ResponseError) Unwrap() error {
	return errors.Join(e.readErr, e.closeErr)
}
