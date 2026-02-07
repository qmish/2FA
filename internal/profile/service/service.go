package service

import (
	"context"
	"errors"

	"github.com/qmish/2FA/internal/dto"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/internal/repository"
)

type Service struct {
	devices repository.DeviceRepository
	logins  repository.LoginHistoryRepository
}

var (
	ErrNotFound     = errors.New("not found")
	ErrInvalidInput = errors.New("invalid input")
)

func NewService(devices repository.DeviceRepository, logins repository.LoginHistoryRepository) *Service {
	return &Service{devices: devices, logins: logins}
}

func (s *Service) ListDevices(ctx context.Context, userID string) (dto.UserDeviceListResponse, error) {
	items, err := s.devices.ListByUser(ctx, userID)
	if err != nil {
		return dto.UserDeviceListResponse{}, err
	}
	out := make([]dto.UserDeviceDTO, 0, len(items))
	for _, item := range items {
		out = append(out, toUserDeviceDTO(item))
	}
	return dto.UserDeviceListResponse{Items: out}, nil
}

func (s *Service) ListLoginHistory(ctx context.Context, userID string, page dto.PageRequest) (dto.UserLoginHistoryResponse, error) {
	items, total, err := s.logins.List(ctx, repository.LoginHistoryFilter{UserID: userID}, page.Limit, page.Offset)
	if err != nil {
		return dto.UserLoginHistoryResponse{}, err
	}
	out := make([]dto.UserLoginHistoryDTO, 0, len(items))
	for _, item := range items {
		out = append(out, toUserLoginHistoryDTO(item))
	}
	return dto.UserLoginHistoryResponse{
		Items: out,
		Page: dto.PageResponse{
			Total:  total,
			Limit:  page.Limit,
			Offset: page.Offset,
		},
	}, nil
}

func (s *Service) DisableDevice(ctx context.Context, userID string, deviceID string) error {
	if deviceID == "" || userID == "" {
		return ErrInvalidInput
	}
	items, err := s.devices.ListByUser(ctx, userID)
	if err != nil {
		return err
	}
	found := false
	for _, item := range items {
		if item.ID == deviceID {
			found = true
			break
		}
	}
	if !found {
		return ErrNotFound
	}
	return s.devices.Disable(ctx, deviceID)
}

func toUserDeviceDTO(device models.Device) dto.UserDeviceDTO {
	var lastSeenAt *int64
	if device.LastSeenAt != nil {
		value := device.LastSeenAt.Unix()
		lastSeenAt = &value
	}
	return dto.UserDeviceDTO{
		ID:         device.ID,
		Type:       device.Type,
		Name:       device.Name,
		Status:     device.Status,
		LastSeenAt: lastSeenAt,
		CreatedAt:  device.CreatedAt.Unix(),
	}
}

func toUserLoginHistoryDTO(item models.LoginHistory) dto.UserLoginHistoryDTO {
	return dto.UserLoginHistoryDTO{
		ID:        item.ID,
		Channel:   item.Channel,
		Result:    item.Result,
		IP:        item.IP,
		DeviceID:  item.DeviceID,
		CreatedAt: item.CreatedAt.Unix(),
	}
}
