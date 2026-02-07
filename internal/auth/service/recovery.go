package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/google/uuid"

	"github.com/qmish/2FA/internal/dto"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/internal/repository"
)

const recoveryCodesCount = 10

func (s *Service) GenerateRecoveryCodes(ctx context.Context, userID string) (dto.RecoveryCodesResponse, error) {
	if s.recoveryCodes == nil {
		return dto.RecoveryCodesResponse{}, ErrNotConfigured
	}
	if _, err := s.users.GetByID(ctx, userID); err != nil {
		if err == repository.ErrNotFound {
			return dto.RecoveryCodesResponse{}, ErrNotFound
		}
		return dto.RecoveryCodesResponse{}, err
	}
	codes, err := generateRecoveryCodes(recoveryCodesCount)
	if err != nil {
		return dto.RecoveryCodesResponse{}, err
	}
	now := s.now()
	items := make([]models.RecoveryCode, 0, len(codes))
	for _, code := range codes {
		items = append(items, models.RecoveryCode{
			ID:        uuid.NewString(),
			UserID:    userID,
			CodeHash:  hash(code),
			CreatedAt: now,
		})
	}
	if err := s.recoveryCodes.DeleteByUser(ctx, userID); err != nil {
		return dto.RecoveryCodesResponse{}, err
	}
	if err := s.recoveryCodes.CreateMany(ctx, items); err != nil {
		return dto.RecoveryCodesResponse{}, err
	}
	return dto.RecoveryCodesResponse{Codes: codes}, nil
}

func generateRecoveryCodes(count int) ([]string, error) {
	result := make([]string, 0, count)
	seen := map[string]struct{}{}
	for len(result) < count {
		code, err := generateRecoveryCode()
		if err != nil {
			return nil, err
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		result = append(result, code)
	}
	return result, nil
}

func generateRecoveryCode() (string, error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(10), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%010d", n.Int64()), nil
}
