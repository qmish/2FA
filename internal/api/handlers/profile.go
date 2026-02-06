package handlers

import (
	"context"
	"net/http"

	"github.com/qmish/2FA/internal/api/middlewares"
	"github.com/qmish/2FA/internal/dto"
)

type ProfileService interface {
	ListDevices(ctx context.Context, userID string) (dto.UserDeviceListResponse, error)
	ListLoginHistory(ctx context.Context, userID string, page dto.PageRequest) (dto.UserLoginHistoryResponse, error)
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
