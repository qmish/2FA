package repository

import (
    "context"
    "time"

    "github.com/qmish/2FA/internal/models"
)

type UserRepository interface {
    GetByID(ctx context.Context, id string) (*models.User, error)
    GetByUsername(ctx context.Context, username string) (*models.User, error)
    GetByUsernameAndRole(ctx context.Context, username string, role models.UserRole) (*models.User, error)
    Create(ctx context.Context, u *models.User) error
    Update(ctx context.Context, u *models.User) error
    SetStatus(ctx context.Context, id string, status models.UserStatus) error
}

type SessionRepository interface {
    Create(ctx context.Context, s *models.UserSession) error
    Revoke(ctx context.Context, id string, revokedAt time.Time) error
    GetByRefreshHash(ctx context.Context, hash string) (*models.UserSession, error)
}

type DeviceRepository interface {
    ListByUser(ctx context.Context, userID string) ([]models.Device, error)
    Upsert(ctx context.Context, d *models.Device) error
    Disable(ctx context.Context, id string) error
}

type PolicyRepository interface {
    GetByID(ctx context.Context, id string) (*models.Policy, error)
    List(ctx context.Context) ([]models.Policy, error)
    Create(ctx context.Context, p *models.Policy) error
    Update(ctx context.Context, p *models.Policy) error
    SetStatus(ctx context.Context, id string, status models.PolicyStatus) error
}

type PolicyRuleRepository interface {
    ListByPolicy(ctx context.Context, policyID string) ([]models.PolicyRule, error)
    Create(ctx context.Context, r *models.PolicyRule) error
    Delete(ctx context.Context, id string) error
}

type RadiusClientRepository interface {
    GetByIP(ctx context.Context, ip string) (*models.RadiusClient, error)
    List(ctx context.Context) ([]models.RadiusClient, error)
    Create(ctx context.Context, c *models.RadiusClient) error
    Update(ctx context.Context, c *models.RadiusClient) error
    SetEnabled(ctx context.Context, id string, enabled bool) error
}

type AuditRepository interface {
    Create(ctx context.Context, e *models.AuditEvent) error
    ListByActor(ctx context.Context, actorUserID string, limit int) ([]models.AuditEvent, error)
    ListByEntity(ctx context.Context, entityType models.AuditEntityType, entityID string, limit int) ([]models.AuditEvent, error)
}

type LoginHistoryRepository interface {
    Create(ctx context.Context, h *models.LoginHistory) error
    ListByUser(ctx context.Context, userID string, limit int) ([]models.LoginHistory, error)
    ListByChannel(ctx context.Context, channel models.AuthChannel, limit int) ([]models.LoginHistory, error)
    ListByPeriod(ctx context.Context, from, to time.Time, limit int) ([]models.LoginHistory, error)
}

type RadiusRequestRepository interface {
    Create(ctx context.Context, r *models.RadiusRequest) error
    ListByClient(ctx context.Context, clientID string, limit int) ([]models.RadiusRequest, error)
    ListByUser(ctx context.Context, username string, limit int) ([]models.RadiusRequest, error)
    UpdateResult(ctx context.Context, id string, result models.RadiusResult) error
}
