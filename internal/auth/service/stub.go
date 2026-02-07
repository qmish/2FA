package service

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/qmish/2FA/internal/dto"
)

var ErrNotImplemented = errors.New("not implemented")

type StubAuthService struct{}

func (s StubAuthService) Login(ctx context.Context, req dto.LoginRequest) (dto.LoginResponse, error) {
	_ = ctx
	_ = req
	return dto.LoginResponse{}, ErrNotImplemented
}

func (s StubAuthService) Register(ctx context.Context, req dto.RegisterRequest) (dto.RegisterResponse, error) {
	_ = ctx
	_ = req
	return dto.RegisterResponse{}, ErrNotImplemented
}

func (s StubAuthService) VerifySecondFactor(ctx context.Context, req dto.VerifyRequest) (dto.TokenPair, error) {
	_ = ctx
	_ = req
	return dto.TokenPair{}, ErrNotImplemented
}

func (s StubAuthService) Refresh(ctx context.Context, req dto.RefreshRequest, ip string) (dto.TokenPair, error) {
	_ = ctx
	_ = req
	_ = ip
	return dto.TokenPair{}, ErrNotImplemented
}

func (s StubAuthService) Logout(ctx context.Context, userID string, sessionID string, ip string) error {
	_ = ctx
	_ = userID
	_ = sessionID
	_ = ip
	return ErrNotImplemented
}

func (s StubAuthService) SetupTOTP(ctx context.Context, userID string) (dto.TOTPSetupResponse, error) {
	_ = ctx
	_ = userID
	return dto.TOTPSetupResponse{}, ErrNotImplemented
}

func (s StubAuthService) DisableTOTP(ctx context.Context, userID string) error {
	_ = ctx
	_ = userID
	return ErrNotImplemented
}

func (s StubAuthService) GenerateRecoveryCodes(ctx context.Context, userID string) (dto.RecoveryCodesResponse, error) {
	_ = ctx
	_ = userID
	return dto.RecoveryCodesResponse{}, ErrNotImplemented
}

func (s StubAuthService) ClearRecoveryCodes(ctx context.Context, userID string) error {
	_ = ctx
	_ = userID
	return ErrNotImplemented
}

func (s StubAuthService) BeginPasskeyRegistration(ctx context.Context, userID string) (dto.PasskeyRegisterBeginResponse, error) {
	_ = ctx
	_ = userID
	return dto.PasskeyRegisterBeginResponse{}, ErrNotImplemented
}

func (s StubAuthService) FinishPasskeyRegistration(ctx context.Context, userID string, credential json.RawMessage) error {
	_ = ctx
	_ = userID
	_ = credential
	return ErrNotImplemented
}

func (s StubAuthService) BeginPasskeyLogin(ctx context.Context) (dto.PasskeyLoginBeginResponse, error) {
	_ = ctx
	return dto.PasskeyLoginBeginResponse{}, ErrNotImplemented
}

func (s StubAuthService) FinishPasskeyLogin(ctx context.Context, sessionID string, credential json.RawMessage, ip string, userAgent string) (dto.TokenPair, error) {
	_ = ctx
	_ = sessionID
	_ = credential
	_ = ip
	_ = userAgent
	return dto.TokenPair{}, ErrNotImplemented
}
