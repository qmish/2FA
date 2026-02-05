package handlers

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestHealth(t *testing.T) {
    req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
    rec := httptest.NewRecorder()

    Health(rec, req)

    if rec.Code != http.StatusOK {
        t.Fatalf("status=%d", rec.Code)
    }
}
