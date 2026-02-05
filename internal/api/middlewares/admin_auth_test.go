package middlewares

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

type fakeValidator struct {
    err   error
    claims *AdminClaims
}

func (v fakeValidator) ParseClaims(token string) (*AdminClaims, error) {
    return v.claims, v.err
}

func TestAdminAuthMiddleware(t *testing.T) {
    handler := AdminAuth(fakeValidator{claims: &AdminClaims{UserID: "u1", Role: "admin"}})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if claims, ok := AdminClaimsFromContext(r.Context()); !ok || claims.UserID != "u1" {
            t.Fatalf("missing claims in context")
        }
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
