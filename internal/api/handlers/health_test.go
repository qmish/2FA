package handlers

import (
    "context"
    "errors"
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

func TestHealthRedisUnavailable(t *testing.T) {
    handler := NewHealthHandler(nil, fakeRedisPinger{err: errRedisDown})
    req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
    rec := httptest.NewRecorder()

    handler.Health(rec, req)
    if rec.Code != http.StatusServiceUnavailable {
        t.Fatalf("status=%d", rec.Code)
    }
}

var errRedisDown = errors.New("redis down")

type fakeRedisPinger struct {
    err error
}

func (f fakeRedisPinger) Ping(ctx context.Context) error {
    return f.err
}
