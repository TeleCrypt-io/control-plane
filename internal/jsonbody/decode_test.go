package jsonbody

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodeAcceptsOneValueAndWhitespace(t *testing.T) {
	var got map[string]string
	if err := Decode(strings.NewReader("{\"token\":\"ok\"} \n\t"), &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got["token"] != "ok" {
		t.Fatalf("decoded value = %#v", got)
	}
}

func TestDecodeRejectsTrailingJSONAndData(t *testing.T) {
	for _, body := range []string{`{"a":1}{"b":2}`, `{"a":1} trailing`} {
		var got map[string]int
		err := Decode(strings.NewReader(body), &got)
		if !errors.Is(err, ErrTrailingData) {
			t.Errorf("Decode(%q) = %v, want trailing-data error", body, err)
		}
	}
}

func TestDecodeErrorRetainsCompleteSanitizedInput(t *testing.T) {
	const secret = "body-secret"
	body := `{"ok":1,"token":"` + secret + `"}{"extra":2}`
	var got map[string]any
	err := Decode(strings.NewReader(body), &got, secret)
	if !errors.Is(err, ErrTrailingData) {
		t.Fatalf("Decode() error = %v, want ErrTrailingData", err)
	}
	var decodeErr *DecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("Decode() error = %T, want *DecodeError", err)
	}
	if !strings.Contains(decodeErr.Body, `"extra":2`) || !strings.Contains(decodeErr.Body, "[REDACTED]") || strings.Contains(decodeErr.Body, secret) {
		t.Fatalf("DecodeError body = %q, want complete sanitized input", decodeErr.Body)
	}
}

func TestDecodeErrorPreservesReadFailureAndPartialBody(t *testing.T) {
	const secret = "partial-secret"
	readErr := errors.New("response read failed")
	r := &errorReader{data: []byte(`{"token":"` + secret + `" tail`), err: readErr}
	var got map[string]string
	err := Decode(r, &got, secret)
	if !errors.Is(err, readErr) {
		t.Fatalf("Decode() error = %v, want read failure", err)
	}
	var decodeErr *DecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("Decode() error = %T, want *DecodeError", err)
	}
	if !strings.Contains(decodeErr.Body, "[REDACTED]") || strings.Contains(decodeErr.Body, secret) {
		t.Fatalf("DecodeError body = %q, want sanitized partial input", decodeErr.Body)
	}
	if !strings.Contains(err.Error(), "response read failed") {
		t.Fatalf("Decode() error = %v, want read detail", err)
	}
}

type errorReader struct {
	data []byte
	err  error
}

func (r *errorReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}

func TestDecodeReadsCompleteBody(t *testing.T) {
	value := strings.Repeat("x", 1<<20)
	var got map[string]string
	if err := Decode(strings.NewReader(`{"token":"`+value+`"}`), &got); err != nil {
		t.Fatalf("Decode complete body: %v", err)
	}
	if got["token"] != value {
		t.Fatalf("decoded value length = %d, want %d", len(got["token"]), len(value))
	}
}
