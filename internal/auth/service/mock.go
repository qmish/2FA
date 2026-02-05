package service

import (
    "context"

    "github.com/qmish/2FA/internal/dto"
)

type MockAuthService struct {
    LoginFunc  func(ctx context.Context, req dto.LoginRequest) (dto.LoginResponse, error)
    VerifyFunc func(ctx context.Context, req dto.VerifyRequest) (dto.TokenPair, error)
    RefreshFunc func(ctx context.Context, req dto.RefreshRequest) (dto.TokenPair, error)
    LogoutFunc func(ctx context.Context, sessionID string) error
}

func (m *MockAuthService) Login(ctx context.Context, req dto.LoginRequest) (dto.LoginResponse, error) {
    return m.LoginFunc(ctx, req)
}

func (m *MockAuthService) VerifySecondFactor(ctx context.Context, req dto.VerifyRequest) (dto.TokenPair, error) {
    return m.VerifyFunc(ctx, req)
}

func (m *MockAuthService) Refresh(ctx context.Context, req dto.RefreshRequest) (dto.TokenPair, error) {
    return m.RefreshFunc(ctx, req)
}

func (m *MockAuthService) Logout(ctx context.Context, sessionID string) error {
    return m.LogoutFunc(ctx, sessionID)
}
