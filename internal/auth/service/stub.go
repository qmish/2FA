package service

import (
	"context"
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
