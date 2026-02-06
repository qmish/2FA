package service

import (
    "context"
    "errors"
    "time"

    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/models"
    "github.com/qmish/2FA/internal/repository"
)

var ErrNotFound = errors.New("not found")

type Service struct {
    sessions repository.SessionRepository
    audits   repository.AuditRepository
    now      func() time.Time
}

func NewService(sessions repository.SessionRepository) *Service {
    return &Service{
        sessions: sessions,
        audits:   nil,
        now:      time.Now,
    }
}

func NewServiceWithAudit(sessions repository.SessionRepository, audits repository.AuditRepository) *Service {
    return &Service{
        sessions: sessions,
        audits:   audits,
        now:      time.Now,
    }
}

func (s *Service) ListUserSessions(ctx context.Context, userID string, activeOnly bool, page dto.PageRequest) (dto.SessionListResponse, error) {
    items, total, err := s.sessions.List(ctx, repository.SessionListFilter{UserID: userID, ActiveOnly: activeOnly}, page.Limit, page.Offset)
    if err != nil {
        return dto.SessionListResponse{}, err
    }
    out := make([]dto.SessionDTO, 0, len(items))
    for _, item := range items {
        out = append(out, toSessionDTO(item))
    }
    return dto.SessionListResponse{
        Items: out,
        Page: dto.PageResponse{
            Total:  total,
            Limit:  page.Limit,
            Offset: page.Offset,
        },
    }, nil
}

func (s *Service) CurrentSession(ctx context.Context, userID string, sessionID string) (dto.SessionDTO, error) {
    sess, err := s.sessions.GetByID(ctx, sessionID)
    if err != nil || sess.UserID != userID {
        return dto.SessionDTO{}, ErrNotFound
    }
    return toSessionDTO(*sess), nil
}

func (s *Service) RevokeSession(ctx context.Context, userID, sessionID, ip string) error {
    sess, err := s.sessions.GetByID(ctx, sessionID)
    if err != nil || sess.UserID != userID {
        return ErrNotFound
    }
    if err := s.sessions.Revoke(ctx, sessionID, s.now()); err != nil {
        return err
    }
	s.audit(ctx, userID, models.AuditSessionRevoke, sessionID, ip)
    return nil
}

func (s *Service) RevokeAll(ctx context.Context, userID, exceptSessionID, ip string) error {
    if err := s.sessions.RevokeAllByUser(ctx, userID, exceptSessionID, s.now()); err != nil {
        return err
    }
	s.audit(ctx, userID, models.AuditSessionRevokeAll, exceptSessionID, ip)
    return nil
}

func toSessionDTO(sess models.UserSession) dto.SessionDTO {
    var revokedAt *int64
    if sess.RevokedAt != nil {
        t := sess.RevokedAt.Unix()
        revokedAt = &t
    }
    var lastSeenAt *int64
    if sess.LastSeenAt != nil {
        t := sess.LastSeenAt.Unix()
        lastSeenAt = &t
    }
    return dto.SessionDTO{
        ID:        sess.ID,
        IP:        sess.IP,
        UserAgent: sess.UserAgent,
        CreatedAt: sess.CreatedAt.Unix(),
        ExpiresAt: sess.ExpiresAt.Unix(),
        LastSeenAt: lastSeenAt,
        RevokedAt: revokedAt,
    }
}

func (s *Service) audit(ctx context.Context, userID string, action models.AuditAction, entityID string, ip string) {
    if s.audits == nil || userID == "" {
        return
    }
    _ = s.audits.Create(ctx, &models.AuditEvent{
        ID:          s.now().Format("20060102150405.000"),
        ActorUserID: userID,
        Action:      action,
        EntityType:  models.AuditEntitySession,
        EntityID:    entityID,
		IP:          ip,
        CreatedAt:   s.now(),
    })
}
