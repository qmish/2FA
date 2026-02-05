package handlers

import (
    "encoding/json"
    "net/http"

    "github.com/qmish/2FA/internal/admin/auth"
    "github.com/qmish/2FA/internal/dto"
)

type AdminAuthHandler struct {
    service *auth.Service
}

func NewAdminAuthHandler(svc *auth.Service) *AdminAuthHandler {
    return &AdminAuthHandler{service: svc}
}

func (h *AdminAuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    var req dto.AdminLoginRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    resp, err := h.service.Login(r.Context(), req)
    if err != nil {
        writeError(w, http.StatusUnauthorized, "admin_login_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}
