package main

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestServeHTTPWithShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := &http.Server{
		Addr:    "127.0.0.1:0",
		Handler: http.NewServeMux(),
	}

	done := make(chan error, 1)
	go func() {
		done <- serveHTTPWithShutdown(ctx, server, 2*time.Second)
	}()

	time.Sleep(25 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for shutdown")
	}
}
