package httpdiag

import (
	"io"
	"strings"
	"testing"
)

func TestReadAndClosePreservesCompleteRawResponseBody(t *testing.T) {
	body := `{"password":"fixture-password","access_token":"fixture-access-token"}` + strings.Repeat("x", 300<<10)
	got, readErr, closeErr := ReadAndClose(io.NopCloser(strings.NewReader(body)))
	if readErr != nil || closeErr != nil {
		t.Fatalf("ReadAndClose errors = (%v, %v), want nil", readErr, closeErr)
	}
	if got != body {
		t.Fatalf("ReadAndClose returned %d bytes, want complete %d-byte body", len(got), len(body))
	}

	err := NewResponseError("upstream", 502, got, nil, nil)
	diagnostic, ok := err.(*ResponseError)
	if !ok {
		t.Fatalf("NewResponseError returned %T, want *ResponseError", err)
	}
	if diagnostic.Body != body || !strings.Contains(err.Error(), "fixture-access-token") {
		t.Fatal("response error did not retain complete raw body content")
	}
}
