package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestShutdownHTTPServerReportsDrainDeadline(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()
	responseDone := make(chan error, 1)
	go func() {
		resp, err := testServer.Client().Get(testServer.URL)
		if err == nil {
			resp.Body.Close()
		}
		responseDone <- err
	}()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := shutdownHTTPServer(ctx, testServer.Config)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdownHTTPServer error = %v, want deadline exceeded", err)
	}
	close(release)
	if err := <-responseDone; err != nil {
		t.Fatalf("drained request: %v", err)
	}
}

func TestShutdownPlanAfterFailurePreservesListenerFailure(t *testing.T) {
	listenerErr := errors.New("listener failed")
	if err := shutdownPlanAfterFailure(&http.Server{}, listenerErr); !errors.Is(err, listenerErr) {
		t.Fatalf("shutdownPlanAfterFailure error = %v, want listener failure", err)
	}
}
