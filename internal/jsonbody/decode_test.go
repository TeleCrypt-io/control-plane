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

func TestDecodeErrorRetainsCompleteRawInput(t *testing.T) {
	body := `{"ok":1,"access_token":"fixture-token-value"}{"extra":2}`
	var got map[string]any
	err := Decode(strings.NewReader(body), &got)
	if !errors.Is(err, ErrTrailingData) {
		t.Fatalf("Decode() error = %v, want ErrTrailingData", err)
	}
	var decodeErr *DecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("Decode() error = %T, want *DecodeError", err)
	}
	if decodeErr.Body != body || !strings.Contains(err.Error(), "fixture-token-value") {
		t.Fatalf("DecodeError body = %q, want complete raw input %q", decodeErr.Body, body)
	}
}

func TestDecodeErrorPreservesReadFailureAndPartialBody(t *testing.T) {
	const partialBody = `{"access_token":"partial-token-value" tail`
	readErr := errors.New("response read failed")
	r := &errorReader{data: []byte(partialBody), err: readErr}
	var got map[string]string
	err := Decode(r, &got)
	if !errors.Is(err, readErr) {
		t.Fatalf("Decode() error = %v, want read failure", err)
	}
	var decodeErr *DecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("Decode() error = %T, want *DecodeError", err)
	}
	if decodeErr.Body != partialBody {
		t.Fatalf("DecodeError body = %q, want complete partial input %q", decodeErr.Body, partialBody)
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
