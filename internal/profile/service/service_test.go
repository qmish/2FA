package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/qmish/2FA/internal/dto"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/internal/repository"
)

func TestListDevices(t *testing.T) {
	now := time.Now()
	lastSeen := now.Add(-time.Hour)
	repo := &fakeDeviceRepo{
		items: []models.Device{
			{
				ID:         "d1",
				UserID:     "u1",
				Type:       models.DeviceMobile,
				Name:       "iphone",
				Status:     models.DeviceActive,
				LastSeenAt: &lastSeen,
				CreatedAt:  now.Add(-2 * time.Hour),
			},
		},
	}
	svc := NewService(repo, fakeLoginRepo{}, fakeOTPRepo{}, fakeRecoveryRepo{})
	resp, err := svc.ListDevices(context.Background(), "u1")
	if err != nil {
		t.Fatalf("ListDevices error: %v", err)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("unexpected items: %+v", resp.Items)
	}
	if resp.Items[0].ID != "d1" || resp.Items[0].LastSeenAt == nil {
		t.Fatalf("unexpected device: %+v", resp.Items[0])
	}
}

func TestListLoginHistory(t *testing.T) {
	now := time.Now()
	repo := fakeLoginRepo{
		items: []models.LoginHistory{
			{ID: "l1", UserID: "u1", Channel: models.ChannelWeb, Result: models.AuthSuccess, IP: "127.0.0.1", CreatedAt: now},
		},
		total: 1,
	}
	svc := NewService(&fakeDeviceRepo{}, repo, fakeOTPRepo{}, fakeRecoveryRepo{})
	resp, err := svc.ListLoginHistory(context.Background(), "u1", dto.PageRequest{Limit: 10, Offset: 0})
	if err != nil {
		t.Fatalf("ListLoginHistory error: %v", err)
	}
	if resp.Page.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.Items[0].ID != "l1" || resp.Items[0].CreatedAt == 0 {
		t.Fatalf("unexpected item: %+v", resp.Items[0])
	}
}

func TestDisableDeviceOK(t *testing.T) {
	repo := &fakeDeviceRepo{
		items: []models.Device{
			{ID: "d1", UserID: "u1", Status: models.DeviceActive},
		},
	}
	svc := NewService(repo, fakeLoginRepo{}, fakeOTPRepo{}, fakeRecoveryRepo{})
	if err := svc.DisableDevice(context.Background(), "u1", "d1"); err != nil {
		t.Fatalf("DisableDevice error: %v", err)
	}
	if repo.disabledID != "d1" {
		t.Fatalf("expected device d1 disabled, got %q", repo.disabledID)
	}
}

func TestDisableDeviceNotFound(t *testing.T) {
	repo := &fakeDeviceRepo{
		items: []models.Device{
			{ID: "d1", UserID: "u2", Status: models.DeviceActive},
		},
	}
	svc := NewService(repo, fakeLoginRepo{}, fakeOTPRepo{}, fakeRecoveryRepo{})
	if err := svc.DisableDevice(context.Background(), "u1", "d1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGetFactorsOK(t *testing.T) {
	otp := fakeOTPRepo{active: &models.OTPSecret{ID: "s1", UserID: "u1", Enabled: true}}
	recovery := fakeRecoveryRepo{count: 2}
	svc := NewService(&fakeDeviceRepo{}, fakeLoginRepo{}, otp, recovery)

	resp, err := svc.GetFactors(context.Background(), "u1")
	if err != nil {
		t.Fatalf("GetFactors error: %v", err)
	}
	if !resp.TOTPEnabled || resp.RecoveryCodesAvailable != 2 {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestGetFactorsNotConfigured(t *testing.T) {
	svc := NewService(&fakeDeviceRepo{}, fakeLoginRepo{}, nil, nil)
	if _, err := svc.GetFactors(context.Background(), "u1"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

type fakeDeviceRepo struct {
	items      []models.Device
	err        error
	disabledID string
}

func (f fakeDeviceRepo) ListByUser(ctx context.Context, userID string) ([]models.Device, error) {
	if f.err != nil {
		return nil, f.err
	}
	if userID == "" {
		return nil, nil
	}
	var filtered []models.Device
	for _, item := range f.items {
		if item.UserID == userID {
			filtered = append(filtered, item)
		}
	}
	return filtered, nil
}
func (f fakeDeviceRepo) Upsert(ctx context.Context, d *models.Device) error { return nil }
func (f *fakeDeviceRepo) Disable(ctx context.Context, id string) error {
	f.disabledID = id
	return nil
}

type fakeLoginRepo struct {
	items []models.LoginHistory
	total int
	err   error
}

func (f fakeLoginRepo) Create(ctx context.Context, h *models.LoginHistory) error { return nil }
func (f fakeLoginRepo) List(ctx context.Context, filter repository.LoginHistoryFilter, limit, offset int) ([]models.LoginHistory, int, error) {
	if f.err != nil {
		return nil, 0, f.err
	}
	return f.items, f.total, nil
}
func (f fakeLoginRepo) CountFailures(ctx context.Context, userID string, since time.Time) (int, error) {
	return 0, nil
}

type fakeOTPRepo struct {
	active *models.OTPSecret
}

func (f fakeOTPRepo) GetActiveByUser(ctx context.Context, userID string) (*models.OTPSecret, error) {
	if f.active != nil && f.active.UserID == userID && f.active.Enabled {
		return f.active, nil
	}
	return nil, repository.ErrNotFound
}
func (f fakeOTPRepo) Create(ctx context.Context, s *models.OTPSecret) error { return nil }
func (f fakeOTPRepo) Disable(ctx context.Context, id string) error          { return nil }

type fakeRecoveryRepo struct {
	count int
}

func (f fakeRecoveryRepo) DeleteByUser(ctx context.Context, userID string) error { return nil }
func (f fakeRecoveryRepo) CreateMany(ctx context.Context, codes []models.RecoveryCode) error {
	return nil
}
func (f fakeRecoveryRepo) Consume(ctx context.Context, userID string, codeHash string, usedAt time.Time) (bool, error) {
	return false, nil
}
func (f fakeRecoveryRepo) CountAvailable(ctx context.Context, userID string) (int, error) {
	return f.count, nil
}
