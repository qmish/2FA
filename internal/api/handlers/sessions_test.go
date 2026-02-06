package handlers

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/qmish/2FA/internal/api/middlewares"
    "github.com/qmish/2FA/internal/dto"
    sessionsvc "github.com/qmish/2FA/internal/session/service"
)

func TestSessionListUnauthorized(t *testing.T) {
    handler := NewSessionHandler(mockSessionService{})
    req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
    rec := httptest.NewRecorder()

    handler.List(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestSessionListOK(t *testing.T) {
    handler := NewSessionHandler(mockSessionService{
        listFunc: func(ctx context.Context, userID string, activeOnly bool, page dto.PageRequest) (dto.SessionListResponse, error) {
            if !activeOnly {
                t.Fatalf("expected activeOnly=true")
            }
            return dto.SessionListResponse{}, nil
        },
    })
    req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions?active_only=true", nil)
    req = req.WithContext(middlewares.WithAuthClaims(req.Context(), &middlewares.AuthClaims{UserID: "u1"}))
    rec := httptest.NewRecorder()

    handler.List(rec, req)
    if rec.Code != http.StatusOK {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestSessionRevokeNotFound(t *testing.T) {
    handler := NewSessionHandler(mockSessionService{
        revokeFunc: func(ctx context.Context, userID, sessionID, ip string) error {
            return sessionsvc.ErrNotFound
        },
    })
    body, _ := json.Marshal(dto.SessionRevokeRequest{SessionID: "s1"})
    req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/revoke", bytes.NewReader(body))
    req = req.WithContext(middlewares.WithAuthClaims(req.Context(), &middlewares.AuthClaims{UserID: "u1"}))
    rec := httptest.NewRecorder()

    handler.Revoke(rec, req)
    if rec.Code != http.StatusNotFound {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestSessionRevokeAllOK(t *testing.T) {
    handler := NewSessionHandler(mockSessionService{
        revokeAllFunc: func(ctx context.Context, userID, exceptSessionID, ip string) error {
            if exceptSessionID != "s1" {
                t.Fatalf("expected except s1, got %s", exceptSessionID)
            }
            if ip == "" {
                t.Fatalf("expected ip")
            }
            return nil
        },
    })
    body, _ := json.Marshal(dto.SessionRevokeAllRequest{ExceptCurrent: true})
    req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/revoke_all", bytes.NewReader(body))
    req = req.WithContext(middlewares.WithAuthClaims(req.Context(), &middlewares.AuthClaims{UserID: "u1", SessionID: "s1"}))
    rec := httptest.NewRecorder()

    handler.RevokeAll(rec, req)
    if rec.Code != http.StatusNoContent {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestSessionCurrentNotFound(t *testing.T) {
    handler := NewSessionHandler(mockSessionService{
        currentFunc: func(ctx context.Context, userID string, sessionID string) (dto.SessionDTO, error) {
            return dto.SessionDTO{}, sessionsvc.ErrNotFound
        },
    })
    req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/current", nil)
    req = req.WithContext(middlewares.WithAuthClaims(req.Context(), &middlewares.AuthClaims{UserID: "u1", SessionID: "s1"}))
    rec := httptest.NewRecorder()

    handler.Current(rec, req)
    if rec.Code != http.StatusNotFound {
        t.Fatalf("status=%d", rec.Code)
    }
}

type mockSessionService struct {
    listFunc      func(ctx context.Context, userID string, activeOnly bool, page dto.PageRequest) (dto.SessionListResponse, error)
    currentFunc   func(ctx context.Context, userID string, sessionID string) (dto.SessionDTO, error)
    revokeFunc    func(ctx context.Context, userID, sessionID, ip string) error
    revokeAllFunc func(ctx context.Context, userID, exceptSessionID, ip string) error
}

func (m mockSessionService) ListUserSessions(ctx context.Context, userID string, activeOnly bool, page dto.PageRequest) (dto.SessionListResponse, error) {
    if m.listFunc != nil {
        return m.listFunc(ctx, userID, activeOnly, page)
    }
    return dto.SessionListResponse{}, nil
}

func (m mockSessionService) CurrentSession(ctx context.Context, userID string, sessionID string) (dto.SessionDTO, error) {
    if m.currentFunc != nil {
        return m.currentFunc(ctx, userID, sessionID)
    }
    return dto.SessionDTO{}, nil
}

func (m mockSessionService) RevokeSession(ctx context.Context, userID, sessionID, ip string) error {
    if m.revokeFunc != nil {
        return m.revokeFunc(ctx, userID, sessionID, ip)
    }
    return nil
}

func (m mockSessionService) RevokeAll(ctx context.Context, userID, exceptSessionID, ip string) error {
    if m.revokeAllFunc != nil {
        return m.revokeAllFunc(ctx, userID, exceptSessionID, ip)
    }
    return nil
}
