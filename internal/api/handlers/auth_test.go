package handlers

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/qmish/2FA/internal/auth/service"
    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/models"
)

func TestAuthLoginOK(t *testing.T) {
    svc := &service.MockAuthService{
        LoginFunc: func(ctx context.Context, req dto.LoginRequest) (dto.LoginResponse, error) {
            return dto.LoginResponse{
                UserID:      "u1",
                ChallengeID: "c1",
                Method:      models.MethodOTP,
            }, nil
        },
        VerifyFunc: func(ctx context.Context, req dto.VerifyRequest) (dto.TokenPair, error) {
            return dto.TokenPair{}, nil
        },
        RefreshFunc: func(ctx context.Context, req dto.RefreshRequest) (dto.TokenPair, error) {
            return dto.TokenPair{}, nil
        },
        LogoutFunc: func(ctx context.Context, sessionID string) error {
            return nil
        },
    }

    handler := NewAuthHandler(svc)
    body, _ := json.Marshal(dto.LoginRequest{
        Username: "alice",
        Password: "pass",
        Channel:  models.ChannelWeb,
    })
    req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
    rec := httptest.NewRecorder()

    handler.Login(rec, req)

    if rec.Code != http.StatusOK {
        t.Fatalf("status=%d, body=%s", rec.Code, rec.Body.String())
    }
}

func TestAuthLoginInvalidJSON(t *testing.T) {
    svc := &service.MockAuthService{
        LoginFunc: func(ctx context.Context, req dto.LoginRequest) (dto.LoginResponse, error) {
            return dto.LoginResponse{}, nil
        },
        VerifyFunc: func(ctx context.Context, req dto.VerifyRequest) (dto.TokenPair, error) {
            return dto.TokenPair{}, nil
        },
        RefreshFunc: func(ctx context.Context, req dto.RefreshRequest) (dto.TokenPair, error) {
            return dto.TokenPair{}, nil
        },
        LogoutFunc: func(ctx context.Context, sessionID string) error {
            return nil
        },
    }

    handler := NewAuthHandler(svc)
    req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString("{"))
    rec := httptest.NewRecorder()

    handler.Login(rec, req)

    if rec.Code != http.StatusBadRequest {
        t.Fatalf("status=%d", rec.Code)
    }
}
