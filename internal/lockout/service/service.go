package service

import (
    "context"
    "errors"
    "time"

    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/repository"
)

var ErrNotFound = errors.New("not found")

type Service struct {
    lockouts repository.LockoutRepository
    now      func() time.Time
}

func NewService(lockouts repository.LockoutRepository) *Service {
    return &Service{
        lockouts: lockouts,
        now:      time.Now,
    }
}

func (s *Service) Current(ctx context.Context, userID string, ip string) (dto.LockoutStatusResponse, error) {
    if s.lockouts == nil {
        return dto.LockoutStatusResponse{}, ErrNotFound
    }
    lockout, err := s.lockouts.GetActive(ctx, userID, ip, s.now())
    if err != nil {
        return dto.LockoutStatusResponse{}, ErrNotFound
    }
    return dto.LockoutStatusResponse{
        ID:        lockout.ID,
        UserID:    lockout.UserID,
        IP:        lockout.IP,
        Reason:    lockout.Reason,
        ExpiresAt: lockout.ExpiresAt.Unix(),
    }, nil
}
