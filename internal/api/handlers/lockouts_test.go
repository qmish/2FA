package handlers

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/qmish/2FA/internal/api/middlewares"
    "github.com/qmish/2FA/internal/dto"
    lockoutsvc "github.com/qmish/2FA/internal/lockout/service"
)

func TestLockoutCurrentNotFound(t *testing.T) {
    handler := NewLockoutHandler(mockLockoutService{
        currentFunc: func(ctx context.Context, userID string, ip string) (dto.LockoutStatusResponse, error) {
            return dto.LockoutStatusResponse{}, lockoutsvc.ErrNotFound
        },
    })
    req := httptest.NewRequest(http.MethodGet, "/api/v1/lockouts/current", nil)
    req = req.WithContext(middlewares.WithAuthClaims(req.Context(), &middlewares.AuthClaims{UserID: "u1"}))
    rec := httptest.NewRecorder()

    handler.Current(rec, req)
    if rec.Code != http.StatusNotFound {
        t.Fatalf("status=%d", rec.Code)
    }
}

type mockLockoutService struct {
    currentFunc func(ctx context.Context, userID string, ip string) (dto.LockoutStatusResponse, error)
}

func (m mockLockoutService) Current(ctx context.Context, userID string, ip string) (dto.LockoutStatusResponse, error) {
    if m.currentFunc != nil {
        return m.currentFunc(ctx, userID, ip)
    }
    return dto.LockoutStatusResponse{}, nil
}
