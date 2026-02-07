package service

import (
	"context"
	"encoding/json"

	"github.com/qmish/2FA/internal/dto"
)

type MockAuthService struct {
	LoginFunc                     func(ctx context.Context, req dto.LoginRequest) (dto.LoginResponse, error)
	RegisterFunc                  func(ctx context.Context, req dto.RegisterRequest) (dto.RegisterResponse, error)
	VerifyFunc                    func(ctx context.Context, req dto.VerifyRequest) (dto.TokenPair, error)
	RefreshFunc                   func(ctx context.Context, req dto.RefreshRequest, ip string) (dto.TokenPair, error)
	LogoutFunc                    func(ctx context.Context, userID string, sessionID string, ip string) error
	SetupTOTPFunc                 func(ctx context.Context, userID string) (dto.TOTPSetupResponse, error)
	DisableTOTPFunc               func(ctx context.Context, userID string) error
	GenerateRecoveryCodesFunc     func(ctx context.Context, userID string) (dto.RecoveryCodesResponse, error)
	ClearRecoveryCodesFunc        func(ctx context.Context, userID string) error
	BeginPasskeyRegistrationFunc  func(ctx context.Context, userID string) (dto.PasskeyRegisterBeginResponse, error)
	FinishPasskeyRegistrationFunc func(ctx context.Context, userID string, credential json.RawMessage) error
}

func (m *MockAuthService) Login(ctx context.Context, req dto.LoginRequest) (dto.LoginResponse, error) {
	return m.LoginFunc(ctx, req)
}

func (m *MockAuthService) Register(ctx context.Context, req dto.RegisterRequest) (dto.RegisterResponse, error) {
	return m.RegisterFunc(ctx, req)
}

func (m *MockAuthService) VerifySecondFactor(ctx context.Context, req dto.VerifyRequest) (dto.TokenPair, error) {
	return m.VerifyFunc(ctx, req)
}

func (m *MockAuthService) Refresh(ctx context.Context, req dto.RefreshRequest, ip string) (dto.TokenPair, error) {
	return m.RefreshFunc(ctx, req, ip)
}

func (m *MockAuthService) Logout(ctx context.Context, userID string, sessionID string, ip string) error {
	return m.LogoutFunc(ctx, userID, sessionID, ip)
}

func (m *MockAuthService) SetupTOTP(ctx context.Context, userID string) (dto.TOTPSetupResponse, error) {
	return m.SetupTOTPFunc(ctx, userID)
}

func (m *MockAuthService) DisableTOTP(ctx context.Context, userID string) error {
	return m.DisableTOTPFunc(ctx, userID)
}

func (m *MockAuthService) GenerateRecoveryCodes(ctx context.Context, userID string) (dto.RecoveryCodesResponse, error) {
	return m.GenerateRecoveryCodesFunc(ctx, userID)
}

func (m *MockAuthService) ClearRecoveryCodes(ctx context.Context, userID string) error {
	return m.ClearRecoveryCodesFunc(ctx, userID)
}

func (m *MockAuthService) BeginPasskeyRegistration(ctx context.Context, userID string) (dto.PasskeyRegisterBeginResponse, error) {
	return m.BeginPasskeyRegistrationFunc(ctx, userID)
}

func (m *MockAuthService) FinishPasskeyRegistration(ctx context.Context, userID string, credential json.RawMessage) error {
	return m.FinishPasskeyRegistrationFunc(ctx, userID, credential)
}
