package handlers

import (
    "bytes"
    "context"
    "encoding/json"
    "errors"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/qmish/2FA/internal/auth/service"
    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/models"
)

func TestAuthLoginOK(t *testing.T) {
    svc := newMockAuthService()
    svc.LoginFunc = func(ctx context.Context, req dto.LoginRequest) (dto.LoginResponse, error) {
        return dto.LoginResponse{
            UserID:      "u1",
            ChallengeID: "c1",
            Method:      models.MethodOTP,
        }, nil
    }

    handler := NewAuthHandler(svc)
    body, _ := json.Marshal(dto.LoginRequest{
        Username: "alice",
        Password: "pass",
        Channel:  models.ChannelWeb,
        Method:   models.MethodOTP,
    })
    req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
    rec := httptest.NewRecorder()

    handler.Login(rec, req)

    if rec.Code != http.StatusOK {
        t.Fatalf("status=%d, body=%s", rec.Code, rec.Body.String())
    }
}

func TestAuthLoginInvalidJSON(t *testing.T) {
    svc := newMockAuthService()

    handler := NewAuthHandler(svc)
    req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString("{"))
    rec := httptest.NewRecorder()

    handler.Login(rec, req)

    if rec.Code != http.StatusBadRequest {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestAuthLoginInvalidInput(t *testing.T) {
    svc := newMockAuthService()
    handler := NewAuthHandler(svc)

    body, _ := json.Marshal(dto.LoginRequest{Username: " ", Password: ""})
    req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
    rec := httptest.NewRecorder()

    handler.Login(rec, req)
    if rec.Code != http.StatusBadRequest {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestAuthLoginInvalidMethod(t *testing.T) {
    svc := newMockAuthService()
    handler := NewAuthHandler(svc)

    body, _ := json.Marshal(dto.LoginRequest{Username: "alice", Password: "pass", Method: "invalid"})
    req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
    rec := httptest.NewRecorder()

    handler.Login(rec, req)
    if rec.Code != http.StatusBadRequest {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestAuthLoginInvalidCredentials(t *testing.T) {
    svc := newMockAuthService()
    svc.LoginFunc = func(ctx context.Context, req dto.LoginRequest) (dto.LoginResponse, error) {
        return dto.LoginResponse{}, service.ErrInvalidCredentials
    }
    handler := NewAuthHandler(svc)

    body, _ := json.Marshal(dto.LoginRequest{Username: "alice", Password: "pass"})
    req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
    rec := httptest.NewRecorder()

    handler.Login(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestAuthVerifyChallengeExpired(t *testing.T) {
    svc := newMockAuthService()
    svc.VerifyFunc = func(ctx context.Context, req dto.VerifyRequest) (dto.TokenPair, error) {
        return dto.TokenPair{}, service.ErrChallengeExpired
    }
    handler := NewAuthHandler(svc)

    body, _ := json.Marshal(dto.VerifyRequest{UserID: "u1", ChallengeID: "c1", Code: "123456"})
    req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify", bytes.NewReader(body))
    rec := httptest.NewRecorder()

    handler.Verify(rec, req)
    if rec.Code != http.StatusConflict {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestAuthVerifyInvalidInput(t *testing.T) {
    svc := newMockAuthService()
    handler := NewAuthHandler(svc)

    body, _ := json.Marshal(dto.VerifyRequest{UserID: "u1"})
    req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify", bytes.NewReader(body))
    rec := httptest.NewRecorder()

    handler.Verify(rec, req)
    if rec.Code != http.StatusBadRequest {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestAuthRefreshSessionExpired(t *testing.T) {
    svc := newMockAuthService()
    svc.RefreshFunc = func(ctx context.Context, req dto.RefreshRequest) (dto.TokenPair, error) {
        return dto.TokenPair{}, service.ErrSessionExpired
    }
    handler := NewAuthHandler(svc)

    body, _ := json.Marshal(dto.RefreshRequest{RefreshToken: "token"})
    req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
    rec := httptest.NewRecorder()

    handler.Refresh(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestAuthRefreshInvalidInput(t *testing.T) {
    svc := newMockAuthService()
    handler := NewAuthHandler(svc)

    body, _ := json.Marshal(dto.RefreshRequest{RefreshToken: " "})
    req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
    rec := httptest.NewRecorder()

    handler.Refresh(rec, req)
    if rec.Code != http.StatusBadRequest {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestAuthLogoutInvalidInput(t *testing.T) {
    svc := newMockAuthService()
    handler := NewAuthHandler(svc)

    body, _ := json.Marshal(dto.LogoutRequest{SessionID: ""})
    req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader(body))
    rec := httptest.NewRecorder()

    handler.Logout(rec, req)
    if rec.Code != http.StatusBadRequest {
        t.Fatalf("status=%d", rec.Code)
    }
}

func newMockAuthService() *service.MockAuthService {
    return &service.MockAuthService{
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
}

func TestAuthVerifyChallengeNotFound(t *testing.T) {
    svc := newMockAuthService()
    svc.VerifyFunc = func(ctx context.Context, req dto.VerifyRequest) (dto.TokenPair, error) {
        return dto.TokenPair{}, service.ErrChallengeNotFound
    }
    handler := NewAuthHandler(svc)

    body, _ := json.Marshal(dto.VerifyRequest{UserID: "u1", ChallengeID: "c1", Code: "123456"})
    req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify", bytes.NewReader(body))
    rec := httptest.NewRecorder()

    handler.Verify(rec, req)
    if rec.Code != http.StatusNotFound {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestAuthVerifySecondFactorFailed(t *testing.T) {
    svc := newMockAuthService()
    svc.VerifyFunc = func(ctx context.Context, req dto.VerifyRequest) (dto.TokenPair, error) {
        return dto.TokenPair{}, service.ErrSecondFactorFailed
    }
    handler := NewAuthHandler(svc)

    body, _ := json.Marshal(dto.VerifyRequest{UserID: "u1", ChallengeID: "c1", Code: "000000"})
    req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify", bytes.NewReader(body))
    rec := httptest.NewRecorder()

    handler.Verify(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestAuthRefreshSessionNotFound(t *testing.T) {
    svc := newMockAuthService()
    svc.RefreshFunc = func(ctx context.Context, req dto.RefreshRequest) (dto.TokenPair, error) {
        return dto.TokenPair{}, service.ErrSessionNotFound
    }
    handler := NewAuthHandler(svc)

    body, _ := json.Marshal(dto.RefreshRequest{RefreshToken: "token"})
    req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
    rec := httptest.NewRecorder()

    handler.Refresh(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestAuthLoginServiceError(t *testing.T) {
    svc := newMockAuthService()
    svc.LoginFunc = func(ctx context.Context, req dto.LoginRequest) (dto.LoginResponse, error) {
        return dto.LoginResponse{}, errors.New("boom")
    }
    handler := NewAuthHandler(svc)

    body, _ := json.Marshal(dto.LoginRequest{Username: "alice", Password: "pass"})
    req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
    rec := httptest.NewRecorder()

    handler.Login(rec, req)
    if rec.Code != http.StatusBadRequest {
        t.Fatalf("status=%d", rec.Code)
    }
}
