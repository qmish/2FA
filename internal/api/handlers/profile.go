package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/qmish/2FA/internal/api/middlewares"
	"github.com/qmish/2FA/internal/dto"
	profilesvc "github.com/qmish/2FA/internal/profile/service"
)

type ProfileService interface {
	ListDevices(ctx context.Context, userID string) (dto.UserDeviceListResponse, error)
	ListLoginHistory(ctx context.Context, userID string, page dto.PageRequest) (dto.UserLoginHistoryResponse, error)
	DisableDevice(ctx context.Context, userID string, deviceID string) error
	GetFactors(ctx context.Context, userID string) (dto.UserFactorsResponse, error)
}

type ProfileHandler struct {
	service ProfileService
}

func NewProfileHandler(svc ProfileService) *ProfileHandler {
	return &ProfileHandler{service: svc}
}

func (h *ProfileHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	claims, ok := middlewares.AuthClaimsFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	resp, err := h.service.ListDevices(r.Context(), claims.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "list_devices_failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *ProfileHandler) ListLoginHistory(w http.ResponseWriter, r *http.Request) {
	claims, ok := middlewares.AuthClaimsFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	resp, err := h.service.ListLoginHistory(r.Context(), claims.UserID, parsePage(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, "list_logins_failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *ProfileHandler) DisableDevice(w http.ResponseWriter, r *http.Request) {
	claims, ok := middlewares.AuthClaimsFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req dto.UserDeviceDisableRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	if req.DeviceID == "" {
		writeError(w, http.StatusBadRequest, "invalid_input")
		return
	}
	if err := h.service.DisableDevice(r.Context(), claims.UserID, req.DeviceID); err != nil {
		switch {
		case errors.Is(err, profilesvc.ErrNotFound):
			writeError(w, http.StatusNotFound, "device_not_found")
		case errors.Is(err, profilesvc.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, "invalid_input")
		default:
			writeError(w, http.StatusBadRequest, "disable_device_failed")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ProfileHandler) GetFactors(w http.ResponseWriter, r *http.Request) {
	claims, ok := middlewares.AuthClaimsFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	resp, err := h.service.GetFactors(r.Context(), claims.UserID)
	if err != nil {
		switch {
		case errors.Is(err, profilesvc.ErrNotConfigured):
			writeError(w, http.StatusBadRequest, "factors_not_configured")
		case errors.Is(err, profilesvc.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, "invalid_input")
		default:
			writeError(w, http.StatusBadRequest, "factors_failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
