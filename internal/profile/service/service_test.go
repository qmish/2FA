package service

import (
	"context"
	"testing"
	"time"

	"github.com/qmish/2FA/internal/dto"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/internal/repository"
)

func TestListDevices(t *testing.T) {
	now := time.Now()
	lastSeen := now.Add(-time.Hour)
	repo := fakeDeviceRepo{
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
	svc := NewService(repo, fakeLoginRepo{})
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
	svc := NewService(fakeDeviceRepo{}, repo)
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

type fakeDeviceRepo struct {
	items []models.Device
	err   error
}

func (f fakeDeviceRepo) ListByUser(ctx context.Context, userID string) ([]models.Device, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.items, nil
}
func (f fakeDeviceRepo) Upsert(ctx context.Context, d *models.Device) error { return nil }
func (f fakeDeviceRepo) Disable(ctx context.Context, id string) error       { return nil }

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
