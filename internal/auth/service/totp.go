package service

import (
	"context"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func (s *Service) validateTOTP(ctx context.Context, userID string, code string) bool {
	if code == "" || s.otpSecrets == nil {
		return false
	}
	secret, err := s.otpSecrets.GetActiveByUser(ctx, userID)
	if err != nil {
		return false
	}
	period := uint(secret.Period)
	if period == 0 {
		period = 30
	}
	digits := otp.DigitsSix
	if secret.Digits == 8 {
		digits = otp.DigitsEight
	}
	ok, err := totp.ValidateCustom(code, secret.Secret, s.now(), totp.ValidateOpts{
		Period:    period,
		Skew:      1,
		Digits:    digits,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return false
	}
	return ok
}
