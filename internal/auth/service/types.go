package service

import (
	"context"

	"github.com/qmish/2FA/internal/dto"
)

type AuthService interface {
	Login(ctx context.Context, req dto.LoginRequest) (dto.LoginResponse, error)
	Register(ctx context.Context, req dto.RegisterRequest) (dto.RegisterResponse, error)
	VerifySecondFactor(ctx context.Context, req dto.VerifyRequest) (dto.TokenPair, error)
	Refresh(ctx context.Context, req dto.RefreshRequest, ip string) (dto.TokenPair, error)
	Logout(ctx context.Context, userID string, sessionID string, ip string) error
	SetupTOTP(ctx context.Context, userID string) (dto.TOTPSetupResponse, error)
	DisableTOTP(ctx context.Context, userID string) error
}
