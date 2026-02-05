package handlers

import (
    "encoding/json"
    "net/http"

    "github.com/qmish/2FA/internal/auth/service"
    "github.com/qmish/2FA/internal/dto"
)

type AuthHandler struct {
    service service.AuthService
}

func NewAuthHandler(svc service.AuthService) *AuthHandler {
    return &AuthHandler{service: svc}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    var req dto.LoginRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    resp, err := h.service.Login(r.Context(), req)
    if err != nil {
        writeError(w, http.StatusUnauthorized, "login_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
    var req dto.VerifyRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    resp, err := h.service.VerifySecondFactor(r.Context(), req)
    if err != nil {
        writeError(w, http.StatusUnauthorized, "verify_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
    var req dto.RefreshRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    resp, err := h.service.Refresh(r.Context(), req)
    if err != nil {
        writeError(w, http.StatusUnauthorized, "refresh_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
    var req dto.LogoutRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    if err := h.service.Logout(r.Context(), req.SessionID); err != nil {
        writeError(w, http.StatusBadRequest, "logout_failed")
        return
    }
    w.WriteHeader(http.StatusNoContent)
}
