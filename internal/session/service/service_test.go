package service

import (
    "context"
    "testing"
    "time"

    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/models"
    "github.com/qmish/2FA/internal/repository"
)

func TestListUserSessions(t *testing.T) {
    repo := &fakeSessionRepo{
        items: []models.UserSession{
            {ID: "s1", UserID: "u1", IP: "127.0.0.1", UserAgent: "ua", CreatedAt: time.Unix(10, 0), ExpiresAt: time.Unix(20, 0)},
        },
    }
    svc := NewService(repo)

    resp, err := svc.ListUserSessions(context.Background(), "u1", true, dto.PageRequest{Limit: 10, Offset: 0})
    if err != nil || len(resp.Items) != 1 || resp.Items[0].ID != "s1" {
        t.Fatalf("unexpected response: %+v err=%v", resp, err)
    }
    if !repo.lastFilter.ActiveOnly {
        t.Fatalf("expected activeOnly filter")
    }
}

func TestRevokeSession(t *testing.T) {
    repo := &fakeSessionRepo{
        items: []models.UserSession{
            {ID: "s1", UserID: "u1"},
        },
    }
    svc := NewService(repo)
    if err := svc.RevokeSession(context.Background(), "u1", "s1", "127.0.0.1"); err != nil {
        t.Fatalf("revoke error: %v", err)
    }
    if repo.revokedID != "s1" {
        t.Fatalf("expected revoke s1, got %s", repo.revokedID)
    }
}

func TestRevokeAll(t *testing.T) {
    repo := &fakeSessionRepo{}
    svc := NewService(repo)
    if err := svc.RevokeAll(context.Background(), "u1", "s2", "127.0.0.1"); err != nil {
        t.Fatalf("revoke all error: %v", err)
    }
    if repo.revokedUser != "u1" || repo.exceptID != "s2" {
        t.Fatalf("unexpected revoke all: %+v", repo)
    }
}

func TestCurrentSession(t *testing.T) {
    repo := &fakeSessionRepo{
        items: []models.UserSession{
            {ID: "s1", UserID: "u1"},
        },
    }
    svc := NewService(repo)
    _, err := svc.CurrentSession(context.Background(), "u1", "s1")
    if err != nil {
        t.Fatalf("current session error: %v", err)
    }
}

func TestRevokeSessionAudits(t *testing.T) {
    audits := &fakeAuditRepo{}
    repo := &fakeSessionRepo{
        items: []models.UserSession{
            {ID: "s1", UserID: "u1"},
        },
    }
    svc := NewServiceWithAudit(repo, audits)
    if err := svc.RevokeSession(context.Background(), "u1", "s1", "127.0.0.1"); err != nil {
        t.Fatalf("revoke error: %v", err)
    }
    if audits.count != 1 || audits.lastAction != models.AuditSessionRevoke || audits.lastIP != "127.0.0.1" {
        t.Fatalf("unexpected audit event")
    }
}

func TestRevokeAllAudits(t *testing.T) {
    audits := &fakeAuditRepo{}
    repo := &fakeSessionRepo{}
    svc := NewServiceWithAudit(repo, audits)
    if err := svc.RevokeAll(context.Background(), "u1", "s2", "127.0.0.1"); err != nil {
        t.Fatalf("revoke all error: %v", err)
    }
    if audits.count != 1 || audits.lastAction != models.AuditSessionRevokeAll || audits.lastIP != "127.0.0.1" {
        t.Fatalf("unexpected audit event")
    }
}

type fakeSessionRepo struct {
    items       []models.UserSession
    revokedID   string
    revokedUser string
    exceptID    string
    lastFilter  repository.SessionListFilter
}

func (f *fakeSessionRepo) Create(ctx context.Context, s *models.UserSession) error { return nil }
func (f *fakeSessionRepo) Revoke(ctx context.Context, id string, revokedAt time.Time) error {
    f.revokedID = id
    return nil
}
func (f *fakeSessionRepo) GetByRefreshHash(ctx context.Context, hash string) (*models.UserSession, error) {
    return nil, repository.ErrNotFound
}
func (f *fakeSessionRepo) GetByID(ctx context.Context, id string) (*models.UserSession, error) {
    for _, item := range f.items {
        if item.ID == id {
            return &item, nil
        }
    }
    return nil, repository.ErrNotFound
}
func (f *fakeSessionRepo) RotateRefreshHash(ctx context.Context, id string, newHash string) error { return nil }
func (f *fakeSessionRepo) List(ctx context.Context, filter repository.SessionListFilter, limit, offset int) ([]models.UserSession, int, error) {
    f.lastFilter = filter
    var out []models.UserSession
    for _, item := range f.items {
        if filter.UserID == "" || item.UserID == filter.UserID {
            out = append(out, item)
        }
    }
    return out, len(out), nil
}
func (f *fakeSessionRepo) RevokeAllByUser(ctx context.Context, userID string, exceptSessionID string, revokedAt time.Time) error {
    f.revokedUser = userID
    f.exceptID = exceptSessionID
    return nil
}
func (f *fakeSessionRepo) Touch(ctx context.Context, id string, seenAt time.Time) error { return nil }

type fakeAuditRepo struct {
    count int
    lastAction models.AuditAction
    lastIP string
}

func (f *fakeAuditRepo) Create(ctx context.Context, e *models.AuditEvent) error {
    f.count++
    f.lastAction = e.Action
    f.lastIP = e.IP
    return nil
}
func (f *fakeAuditRepo) List(ctx context.Context, filter repository.AuditFilter, limit, offset int) ([]models.AuditEvent, int, error) {
    return nil, 0, nil
}
