package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qmish/2FA/internal/api/middlewares"
	"github.com/qmish/2FA/internal/dto"
	profilesvc "github.com/qmish/2FA/internal/profile/service"
)

func TestProfileDevicesUnauthorized(t *testing.T) {
	h := NewProfileHandler(profileMock{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/profile/devices", nil)
	rr := httptest.NewRecorder()

	h.ListDevices(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestProfileDevicesOK(t *testing.T) {
	mock := profileMock{
		devicesResp: dto.UserDeviceListResponse{
			Items: []dto.UserDeviceDTO{{ID: "d1"}},
		},
	}
	h := NewProfileHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/profile/devices", nil)
	req = req.WithContext(middlewares.WithAuthClaims(req.Context(), &middlewares.AuthClaims{UserID: "u1"}))
	rr := httptest.NewRecorder()

	h.ListDevices(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp dto.UserDeviceListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(resp.Items) != 1 || resp.Items[0].ID != "d1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestProfileLoginsUnauthorized(t *testing.T) {
	h := NewProfileHandler(profileMock{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/profile/logins", nil)
	rr := httptest.NewRecorder()

	h.ListLoginHistory(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestProfileLoginsOK(t *testing.T) {
	mock := profileMock{
		loginsResp: dto.UserLoginHistoryResponse{
			Items: []dto.UserLoginHistoryDTO{{ID: "l1"}},
			Page:  dto.PageResponse{Total: 1, Limit: 10, Offset: 0},
		},
	}
	h := NewProfileHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/profile/logins?limit=10", nil)
	req = req.WithContext(middlewares.WithAuthClaims(req.Context(), &middlewares.AuthClaims{UserID: "u1"}))
	rr := httptest.NewRecorder()

	h.ListLoginHistory(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp dto.UserLoginHistoryResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(resp.Items) != 1 || resp.Items[0].ID != "l1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestProfileDisableDeviceUnauthorized(t *testing.T) {
	h := NewProfileHandler(profileMock{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/profile/devices/disable", nil)
	rr := httptest.NewRecorder()

	h.DisableDevice(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestProfileDisableDeviceOK(t *testing.T) {
	mock := profileMock{}
	h := NewProfileHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/profile/devices/disable", strings.NewReader(`{"device_id":"d1"}`))
	req = req.WithContext(middlewares.WithAuthClaims(req.Context(), &middlewares.AuthClaims{UserID: "u1"}))
	rr := httptest.NewRecorder()

	h.DisableDevice(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}

func TestProfileDisableDeviceNotFound(t *testing.T) {
	mock := profileMock{disableErr: profilesvc.ErrNotFound}
	h := NewProfileHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/profile/devices/disable", strings.NewReader(`{"device_id":"d1"}`))
	req = req.WithContext(middlewares.WithAuthClaims(req.Context(), &middlewares.AuthClaims{UserID: "u1"}))
	rr := httptest.NewRecorder()

	h.DisableDevice(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

type profileMock struct {
	devicesResp dto.UserDeviceListResponse
	loginsResp  dto.UserLoginHistoryResponse
	disableErr  error
}

func (p profileMock) ListDevices(ctx context.Context, userID string) (dto.UserDeviceListResponse, error) {
	return p.devicesResp, nil
}

func (p profileMock) ListLoginHistory(ctx context.Context, userID string, page dto.PageRequest) (dto.UserLoginHistoryResponse, error) {
	return p.loginsResp, nil
}

func (p profileMock) DisableDevice(ctx context.Context, userID string, deviceID string) error {
	return p.disableErr
}
