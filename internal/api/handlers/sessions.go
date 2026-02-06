package handlers

import (
    "context"
    "encoding/json"
    "net/http"

    "github.com/qmish/2FA/internal/api/middlewares"
    "github.com/qmish/2FA/internal/dto"
    sessionsvc "github.com/qmish/2FA/internal/session/service"
)

type SessionService interface {
    ListUserSessions(ctx context.Context, userID string, activeOnly bool, page dto.PageRequest) (dto.SessionListResponse, error)
    CurrentSession(ctx context.Context, userID string, sessionID string) (dto.SessionDTO, error)
    RevokeSession(ctx context.Context, userID, sessionID, ip string) error
    RevokeAll(ctx context.Context, userID, exceptSessionID, ip string) error
}

type SessionHandler struct {
    service SessionService
}

func NewSessionHandler(svc SessionService) *SessionHandler {
    return &SessionHandler{service: svc}
}

func (h *SessionHandler) List(w http.ResponseWriter, r *http.Request) {
    claims, ok := middlewares.AuthClaimsFromContext(r.Context())
    if !ok {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }
    resp, err := h.service.ListUserSessions(r.Context(), claims.UserID, parseBool(r.URL.Query().Get("active_only")), parsePage(r))
    if err != nil {
        writeError(w, http.StatusBadRequest, "list_sessions_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *SessionHandler) Current(w http.ResponseWriter, r *http.Request) {
    claims, ok := middlewares.AuthClaimsFromContext(r.Context())
    if !ok {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }
    resp, err := h.service.CurrentSession(r.Context(), claims.UserID, claims.SessionID)
    if err != nil {
        if err == sessionsvc.ErrNotFound {
            writeError(w, http.StatusNotFound, "session_not_found")
            return
        }
        writeError(w, http.StatusBadRequest, "session_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *SessionHandler) Revoke(w http.ResponseWriter, r *http.Request) {
    claims, ok := middlewares.AuthClaimsFromContext(r.Context())
    if !ok {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }
    var req dto.SessionRevokeRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    if req.SessionID == "" {
        writeError(w, http.StatusBadRequest, "invalid_input")
        return
    }
    if err := h.service.RevokeSession(r.Context(), claims.UserID, req.SessionID, clientIP(r)); err != nil {
        if err == sessionsvc.ErrNotFound {
            writeError(w, http.StatusNotFound, "session_not_found")
            return
        }
        writeError(w, http.StatusBadRequest, "revoke_failed")
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func (h *SessionHandler) RevokeAll(w http.ResponseWriter, r *http.Request) {
    claims, ok := middlewares.AuthClaimsFromContext(r.Context())
    if !ok {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }
    var req dto.SessionRevokeAllRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    except := ""
    if req.ExceptCurrent {
        except = claims.SessionID
    }
    if err := h.service.RevokeAll(r.Context(), claims.UserID, except, clientIP(r)); err != nil {
        writeError(w, http.StatusBadRequest, "revoke_failed")
        return
    }
    w.WriteHeader(http.StatusNoContent)
}
