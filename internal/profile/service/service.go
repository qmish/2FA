package service

import (
	"context"
	"errors"

	"github.com/qmish/2FA/internal/dto"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/internal/repository"
)

type Service struct {
	devices       repository.DeviceRepository
	logins        repository.LoginHistoryRepository
	otpSecrets    repository.OTPSecretRepository
	recoveryCodes repository.RecoveryCodeRepository
	webauthnCreds repository.WebAuthnCredentialRepository
}

var (
	ErrNotFound      = errors.New("not found")
	ErrInvalidInput  = errors.New("invalid input")
	ErrNotConfigured = errors.New("not configured")
)

func NewService(
	devices repository.DeviceRepository,
	logins repository.LoginHistoryRepository,
	otpSecrets repository.OTPSecretRepository,
	recoveryCodes repository.RecoveryCodeRepository,
	webauthnCreds repository.WebAuthnCredentialRepository,
) *Service {
	return &Service{
		devices:       devices,
		logins:        logins,
		otpSecrets:    otpSecrets,
		recoveryCodes: recoveryCodes,
		webauthnCreds: webauthnCreds,
	}
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

func (s *Service) GetFactors(ctx context.Context, userID string) (dto.UserFactorsResponse, error) {
	if userID == "" {
		return dto.UserFactorsResponse{}, ErrInvalidInput
	}
	if s.otpSecrets == nil || s.recoveryCodes == nil {
		return dto.UserFactorsResponse{}, ErrNotConfigured
	}
	resp := dto.UserFactorsResponse{}
	if _, err := s.otpSecrets.GetActiveByUser(ctx, userID); err == nil {
		resp.TOTPEnabled = true
	} else if !errors.Is(err, repository.ErrNotFound) {
		return dto.UserFactorsResponse{}, err
	}
	count, err := s.recoveryCodes.CountAvailable(ctx, userID)
	if err != nil {
		return dto.UserFactorsResponse{}, err
	}
	resp.RecoveryCodesAvailable = count
	return resp, nil
}

func (s *Service) ListPasskeys(ctx context.Context, userID string) (dto.UserPasskeyListResponse, error) {
	if userID == "" {
		return dto.UserPasskeyListResponse{}, ErrInvalidInput
	}
	if s.webauthnCreds == nil {
		return dto.UserPasskeyListResponse{}, ErrNotConfigured
	}
	items, err := s.webauthnCreds.ListByUser(ctx, userID)
	if err != nil {
		return dto.UserPasskeyListResponse{}, err
	}
	resp := dto.UserPasskeyListResponse{Items: make([]dto.UserPasskeyDTO, 0, len(items))}
	for _, item := range items {
		resp.Items = append(resp.Items, toUserPasskeyDTO(item))
	}
	return resp, nil
}

func (s *Service) DeletePasskey(ctx context.Context, userID string, id string) error {
	if userID == "" || id == "" {
		return ErrInvalidInput
	}
	if s.webauthnCreds == nil {
		return ErrNotConfigured
	}
	ok, err := s.webauthnCreds.DeleteByID(ctx, userID, id)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	return nil
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

func toUserPasskeyDTO(item models.WebAuthnCredential) dto.UserPasskeyDTO {
	var lastUsedAt *int64
	if item.LastUsedAt != nil {
		value := item.LastUsedAt.Unix()
		lastUsedAt = &value
	}
	return dto.UserPasskeyDTO{
		ID:           item.ID,
		CredentialID: item.CredentialID,
		SignCount:    item.SignCount,
		CreatedAt:    item.CreatedAt.Unix(),
		LastUsedAt:   lastUsedAt,
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
