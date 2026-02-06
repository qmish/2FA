package handlers

import (
    "context"
    "net"
    "net/http"
    "strings"

    "github.com/qmish/2FA/internal/api/middlewares"
    "github.com/qmish/2FA/internal/dto"
    lockoutsvc "github.com/qmish/2FA/internal/lockout/service"
)

type LockoutService interface {
    Current(ctx context.Context, userID string, ip string) (dto.LockoutStatusResponse, error)
}

type LockoutHandler struct {
    service LockoutService
}

func NewLockoutHandler(svc LockoutService) *LockoutHandler {
    return &LockoutHandler{service: svc}
}

func (h *LockoutHandler) Current(w http.ResponseWriter, r *http.Request) {
    claims, ok := middlewares.AuthClaimsFromContext(r.Context())
    if !ok {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }
    ip := lockoutClientIP(r)
    resp, err := h.service.Current(r.Context(), claims.UserID, ip)
    if err != nil {
        if err == lockoutsvc.ErrNotFound {
            writeError(w, http.StatusNotFound, "lockout_not_found")
            return
        }
        writeError(w, http.StatusBadRequest, "lockout_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func lockoutClientIP(r *http.Request) string {
    forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
    if forwarded != "" {
        parts := strings.Split(forwarded, ",")
        if len(parts) > 0 {
            return strings.TrimSpace(parts[0])
        }
    }
    host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
    if err == nil && host != "" {
        return host
    }
    return strings.TrimSpace(r.RemoteAddr)
}
