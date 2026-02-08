package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandlerOK(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()

	HealthHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if rr.Body.String() != "ok" {
		t.Fatalf("expected body ok, got %q", rr.Body.String())
	}
}
