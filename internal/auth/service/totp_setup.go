package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/qmish/2FA/internal/dto"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/internal/repository"
)

func (s *Service) SetupTOTP(ctx context.Context, userID string) (dto.TOTPSetupResponse, error) {
	if s.otpSecrets == nil {
		return dto.TOTPSetupResponse{}, ErrNotConfigured
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.TOTPSetupResponse{}, ErrNotFound
		}
		return dto.TOTPSetupResponse{}, err
	}
	issuer := s.totpIssuer
	if issuer == "" {
		issuer = "2FA"
	}
	digits := s.totpDigits
	if digits != 8 {
		digits = 6
	}
	period := s.totpPeriod
	if period != 60 {
		period = 30
	}
	account := user.Username
	if account == "" {
		account = user.ID
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
		Period:      uint(period),
		Digits:      otp.Digits(digits),
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return dto.TOTPSetupResponse{}, err
	}
	now := time.Now()
	secret := &models.OTPSecret{
		ID:        uuid.NewString(),
		UserID:    userID,
		Secret:    key.Secret(),
		Issuer:    issuer,
		Digits:    digits,
		Period:    period,
		Enabled:   true,
		CreatedAt: now,
	}
	if err := s.otpSecrets.Create(ctx, secret); err != nil {
		return dto.TOTPSetupResponse{}, err
	}
	return dto.TOTPSetupResponse{
		Secret:     secret.Secret,
		OTPAuthURL: key.URL(),
		Issuer:     issuer,
		Digits:     digits,
		Period:     period,
	}, nil
}

func (s *Service) DisableTOTP(ctx context.Context, userID string) error {
	if s.otpSecrets == nil {
		return ErrNotConfigured
	}
	secret, err := s.otpSecrets.GetActiveByUser(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	return s.otpSecrets.Disable(ctx, secret.ID)
}
