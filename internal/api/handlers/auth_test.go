package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qmish/2FA/internal/api/middlewares"
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

func TestAuthLoginInvalidChannel(t *testing.T) {
	svc := newMockAuthService()
	handler := NewAuthHandler(svc)

	body, _ := json.Marshal(dto.LoginRequest{Username: "alice", Password: "pass", Channel: "invalid"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler.Login(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAuthLoginInvalidEmail(t *testing.T) {
	svc := newMockAuthService()
	handler := NewAuthHandler(svc)

	body, _ := json.Marshal(dto.LoginRequest{Username: "bad@", Password: "pass"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler.Login(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAuthLoginInvalidPhone(t *testing.T) {
	svc := newMockAuthService()
	handler := NewAuthHandler(svc)

	body, _ := json.Marshal(dto.LoginRequest{Username: "+1", Password: "pass"})
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

func TestAuthLoginForbidden(t *testing.T) {
	svc := newMockAuthService()
	svc.LoginFunc = func(ctx context.Context, req dto.LoginRequest) (dto.LoginResponse, error) {
		return dto.LoginResponse{}, service.ErrForbidden
	}
	handler := NewAuthHandler(svc)

	body, _ := json.Marshal(dto.LoginRequest{Username: "alice", Password: "pass"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler.Login(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAuthLoginRateLimited(t *testing.T) {
	svc := newMockAuthService()
	svc.LoginFunc = func(ctx context.Context, req dto.LoginRequest) (dto.LoginResponse, error) {
		return dto.LoginResponse{}, service.ErrRateLimited
	}
	handler := NewAuthHandler(svc)

	body, _ := json.Marshal(dto.LoginRequest{Username: "alice", Password: "pass"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler.Login(rec, req)
	if rec.Code != http.StatusTooManyRequests {
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

func TestAuthVerifyInvalidMethod(t *testing.T) {
	svc := newMockAuthService()
	handler := NewAuthHandler(svc)

	body, _ := json.Marshal(dto.VerifyRequest{UserID: "u1", ChallengeID: "c1", Code: "123456", Method: "invalid"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler.Verify(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAuthRefreshSessionExpired(t *testing.T) {
	svc := newMockAuthService()
	svc.RefreshFunc = func(ctx context.Context, req dto.RefreshRequest, ip string) (dto.TokenPair, error) {
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

func TestAuthLogoutUnauthorized(t *testing.T) {
	svc := newMockAuthService()
	handler := NewAuthHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	rec := httptest.NewRecorder()

	handler.Logout(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAuthLogoutUsesClaimsSession(t *testing.T) {
	svc := newMockAuthService()
	svc.LogoutFunc = func(ctx context.Context, userID string, sessionID string, ip string) error {
		if userID != "u1" || sessionID != "s1" {
			t.Fatalf("expected user u1 session s1, got %s %s", userID, sessionID)
		}
		return nil
	}
	handler := NewAuthHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req = req.WithContext(middlewares.WithAuthClaims(req.Context(), &middlewares.AuthClaims{UserID: "u1", SessionID: "s1"}))
	rec := httptest.NewRecorder()

	handler.Logout(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAuthLogoutSessionMismatch(t *testing.T) {
	svc := newMockAuthService()
	handler := NewAuthHandler(svc)

	body, _ := json.Marshal(dto.LogoutRequest{SessionID: "s2"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader(body))
	req = req.WithContext(middlewares.WithAuthClaims(req.Context(), &middlewares.AuthClaims{UserID: "u1", SessionID: "s1"}))
	rec := httptest.NewRecorder()

	handler.Logout(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAuthLoginInvalidIP(t *testing.T) {
	svc := newMockAuthService()
	handler := NewAuthHandler(svc)

	body, _ := json.Marshal(dto.LoginRequest{Username: "alice", Password: "pass"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.RemoteAddr = "invalid"
	rec := httptest.NewRecorder()

	handler.Login(rec, req)
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
		RefreshFunc: func(ctx context.Context, req dto.RefreshRequest, ip string) (dto.TokenPair, error) {
			return dto.TokenPair{}, nil
		},
		LogoutFunc: func(ctx context.Context, userID string, sessionID string, ip string) error {
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
	svc.RefreshFunc = func(ctx context.Context, req dto.RefreshRequest, ip string) (dto.TokenPair, error) {
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
