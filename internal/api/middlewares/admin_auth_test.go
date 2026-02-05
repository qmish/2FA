package middlewares

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

type fakeValidator struct {
    err error
}

func (v fakeValidator) Validate(token string) error {
    return v.err
}

func TestAdminAuthMiddleware(t *testing.T) {
    handler := AdminAuth(fakeValidator{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))

    req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
    req.Header.Set("Authorization", "Bearer token")
    rec := httptest.NewRecorder()

    handler.ServeHTTP(rec, req)
    if rec.Code != http.StatusOK {
        t.Fatalf("status=%d", rec.Code)
    }
}
