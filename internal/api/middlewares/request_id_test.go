package middlewares

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestRequestIDMiddleware(t *testing.T) {
    handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Header.Get(RequestIDHeader) != "" {
            t.Fatalf("request id should be set in response, not request")
        }
    }))

    req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
    rec := httptest.NewRecorder()

    handler.ServeHTTP(rec, req)

    if rec.Header().Get(RequestIDHeader) == "" {
        t.Fatalf("missing %s header", RequestIDHeader)
    }
}
