package handlers

import (
    "encoding/json"
    "errors"
    "net/http"
    "strings"

    "github.com/qmish/2FA/internal/auth/service"
    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/models"
)

type AuthHandler struct {
    service service.AuthService
}

func NewAuthHandler(svc service.AuthService) *AuthHandler {
    return &AuthHandler{service: svc}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    var req dto.LoginRequest
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields()
    if err := dec.Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    req.Username = strings.TrimSpace(req.Username)
    if req.Username == "" || req.Password == "" {
        writeError(w, http.StatusBadRequest, "invalid_input")
        return
    }
    if req.Method != "" && !isValidSecondFactorMethod(req.Method) {
        writeError(w, http.StatusBadRequest, "invalid_method")
        return
    }
    resp, err := h.service.Login(r.Context(), req)
    if err != nil {
        if errors.Is(err, service.ErrInvalidCredentials) {
            writeError(w, http.StatusUnauthorized, "invalid_credentials")
            return
        }
        writeError(w, http.StatusBadRequest, "login_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
    var req dto.VerifyRequest
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields()
    if err := dec.Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    if req.UserID == "" || req.ChallengeID == "" || req.Code == "" {
        writeError(w, http.StatusBadRequest, "invalid_input")
        return
    }
    resp, err := h.service.VerifySecondFactor(r.Context(), req)
    if err != nil {
        switch {
        case errors.Is(err, service.ErrChallengeNotFound):
            writeError(w, http.StatusNotFound, "challenge_not_found")
        case errors.Is(err, service.ErrChallengeExpired):
            writeError(w, http.StatusConflict, "challenge_expired")
        case errors.Is(err, service.ErrSecondFactorFailed):
            writeError(w, http.StatusUnauthorized, "second_factor_failed")
        default:
            writeError(w, http.StatusBadRequest, "verify_failed")
        }
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
    var req dto.RefreshRequest
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields()
    if err := dec.Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    if strings.TrimSpace(req.RefreshToken) == "" {
        writeError(w, http.StatusBadRequest, "invalid_input")
        return
    }
    resp, err := h.service.Refresh(r.Context(), req)
    if err != nil {
        switch {
        case errors.Is(err, service.ErrSessionNotFound):
            writeError(w, http.StatusUnauthorized, "session_not_found")
        case errors.Is(err, service.ErrSessionExpired):
            writeError(w, http.StatusUnauthorized, "session_expired")
        default:
            writeError(w, http.StatusBadRequest, "refresh_failed")
        }
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
    var req dto.LogoutRequest
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields()
    if err := dec.Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    if req.SessionID == "" {
        writeError(w, http.StatusBadRequest, "invalid_input")
        return
    }
    if err := h.service.Logout(r.Context(), req.SessionID); err != nil {
        writeError(w, http.StatusBadRequest, "logout_failed")
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func isValidSecondFactorMethod(method models.SecondFactorMethod) bool {
    switch method {
    case models.MethodOTP, models.MethodCall, models.MethodPush:
        return true
    default:
        return false
    }
}
