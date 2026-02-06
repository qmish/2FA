package middlewares

import (
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/qmish/2FA/internal/models"
)

type fakeValidator struct {
    err   error
    claims *AdminClaims
}

func (v fakeValidator) ParseClaims(token string) (*AdminClaims, error) {
    return v.claims, v.err
}

func TestAdminAuthMiddleware(t *testing.T) {
    handler := AdminAuth(fakeValidator{claims: &AdminClaims{UserID: "u1", Role: string(models.RoleAdmin)}})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestAdminAuthMiddleware_NonAdminRole(t *testing.T) {
    handler := AdminAuth(fakeValidator{claims: &AdminClaims{UserID: "u1", Role: "user"}})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        t.Fatal("handler should not be called")
    }))

    req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
    req.Header.Set("Authorization", "Bearer token")
    rec := httptest.NewRecorder()

    handler.ServeHTTP(rec, req)
    if rec.Code != http.StatusForbidden {
        t.Fatalf("expected 403, got status=%d", rec.Code)
    }
}

func TestAdminAuthMiddleware_NoToken(t *testing.T) {
    handler := AdminAuth(fakeValidator{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        t.Fatal("handler should not be called")
    }))

    req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
    rec := httptest.NewRecorder()

    handler.ServeHTTP(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("expected 401, got status=%d", rec.Code)
    }
}
