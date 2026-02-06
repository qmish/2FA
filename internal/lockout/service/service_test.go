package service

import (
    "context"
    "testing"
    "time"

    "github.com/qmish/2FA/internal/models"
    "github.com/qmish/2FA/internal/repository"
)

func TestCurrentLockoutNotFound(t *testing.T) {
    svc := NewService(fakeLockoutRepo{})
    _, err := svc.Current(context.Background(), "u1", "127.0.0.1")
    if err != ErrNotFound {
        t.Fatalf("expected ErrNotFound, got %v", err)
    }
}

func TestCurrentLockoutOK(t *testing.T) {
    now := time.Now()
    svc := NewService(fakeLockoutRepo{
        lockout: &models.Lockout{
            ID:        "l1",
            UserID:    "u1",
            IP:        "127.0.0.1",
            Reason:    "too_many_attempts",
            ExpiresAt: now.Add(time.Minute),
            CreatedAt: now,
        },
    })
    got, err := svc.Current(context.Background(), "u1", "127.0.0.1")
    if err != nil || got.ID != "l1" {
        t.Fatalf("unexpected response: %+v err=%v", got, err)
    }
}

type fakeLockoutRepo struct {
    lockout *models.Lockout
}

func (f fakeLockoutRepo) Create(ctx context.Context, l *models.Lockout) error { return nil }
func (f fakeLockoutRepo) GetActive(ctx context.Context, userID string, ip string, now time.Time) (*models.Lockout, error) {
    if f.lockout == nil {
        return nil, repository.ErrNotFound
    }
    return f.lockout, nil
}
func (f fakeLockoutRepo) ClearExpired(ctx context.Context, now time.Time) (int64, error) { return 0, nil }
func (f fakeLockoutRepo) List(ctx context.Context, filter repository.LockoutFilter, limit, offset int) ([]models.Lockout, int, error) {
    return nil, 0, nil
}
func (f fakeLockoutRepo) ClearByFilter(ctx context.Context, filter repository.LockoutFilter) error { return nil }
