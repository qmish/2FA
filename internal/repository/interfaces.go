package repository

import (
    "context"
    "time"

    "github.com/qmish/2FA/internal/models"
)

type UserListFilter struct {
    Query   string
    Status  models.UserStatus
    GroupID string
}

type AuditFilter struct {
    ActorUserID string
    EntityType  models.AuditEntityType
    Action      models.AuditAction
    From        time.Time
    To          time.Time
}

type LoginHistoryFilter struct {
    UserID  string
    Channel models.AuthChannel
    Result  models.AuthResult
    From    time.Time
    To      time.Time
}

type RadiusRequestFilter struct {
    ClientID string
    Username string
    Result   models.RadiusResult
    From     time.Time
    To       time.Time
}

type UserRepository interface {
    GetByID(ctx context.Context, id string) (*models.User, error)
    GetByUsername(ctx context.Context, username string) (*models.User, error)
    GetByUsernameAndRole(ctx context.Context, username string, role models.UserRole) (*models.User, error)
    GetByEmail(ctx context.Context, email string) (*models.User, error)
    GetByPhone(ctx context.Context, phone string) (*models.User, error)
    List(ctx context.Context, filter UserListFilter, limit, offset int) ([]models.User, int, error)
    Create(ctx context.Context, u *models.User) error
    Update(ctx context.Context, u *models.User) error
    Delete(ctx context.Context, id string) error
    SetStatus(ctx context.Context, id string, status models.UserStatus) error
}

type SessionRepository interface {
    Create(ctx context.Context, s *models.UserSession) error
    Revoke(ctx context.Context, id string, revokedAt time.Time) error
    GetByRefreshHash(ctx context.Context, hash string) (*models.UserSession, error)
}

type ChallengeRepository interface {
    GetByID(ctx context.Context, id string) (*models.Challenge, error)
    Create(ctx context.Context, c *models.Challenge) error
    UpdateStatus(ctx context.Context, id string, status models.ChallengeStatus) error
    MarkExpired(ctx context.Context, now time.Time) (int64, error)
}

type DeviceRepository interface {
    ListByUser(ctx context.Context, userID string) ([]models.Device, error)
    Upsert(ctx context.Context, d *models.Device) error
    Disable(ctx context.Context, id string) error
}

type PolicyRepository interface {
    GetByID(ctx context.Context, id string) (*models.Policy, error)
    GetByName(ctx context.Context, name string) (*models.Policy, error)
    List(ctx context.Context, limit, offset int) ([]models.Policy, int, error)
    Create(ctx context.Context, p *models.Policy) error
    Update(ctx context.Context, p *models.Policy) error
    Delete(ctx context.Context, id string) error
    SetStatus(ctx context.Context, id string, status models.PolicyStatus) error
}

type PolicyRuleRepository interface {
    ListByPolicy(ctx context.Context, policyID string) ([]models.PolicyRule, error)
    Create(ctx context.Context, r *models.PolicyRule) error
    Delete(ctx context.Context, id string) error
    DeleteByPolicy(ctx context.Context, policyID string) error
}

type RadiusClientRepository interface {
    GetByID(ctx context.Context, id string) (*models.RadiusClient, error)
    GetByIP(ctx context.Context, ip string) (*models.RadiusClient, error)
    List(ctx context.Context, limit, offset int) ([]models.RadiusClient, int, error)
    Create(ctx context.Context, c *models.RadiusClient) error
    Update(ctx context.Context, c *models.RadiusClient) error
    Delete(ctx context.Context, id string) error
    SetEnabled(ctx context.Context, id string, enabled bool) error
}

type AuditRepository interface {
    Create(ctx context.Context, e *models.AuditEvent) error
    List(ctx context.Context, filter AuditFilter, limit, offset int) ([]models.AuditEvent, int, error)
}

type LoginHistoryRepository interface {
    Create(ctx context.Context, h *models.LoginHistory) error
    List(ctx context.Context, filter LoginHistoryFilter, limit, offset int) ([]models.LoginHistory, int, error)
}

type RadiusRequestRepository interface {
    Create(ctx context.Context, r *models.RadiusRequest) error
    List(ctx context.Context, filter RadiusRequestFilter, limit, offset int) ([]models.RadiusRequest, int, error)
    UpdateResult(ctx context.Context, id string, result models.RadiusResult) error
}

type RolePermissionRepository interface {
    ListByRole(ctx context.Context, role models.UserRole) ([]models.Permission, error)
    SetRolePermissions(ctx context.Context, role models.UserRole, perms []models.Permission) error
}

type GroupRepository interface {
    GetByID(ctx context.Context, id string) (*models.Group, error)
    GetByName(ctx context.Context, name string) (*models.Group, error)
    List(ctx context.Context, limit, offset int) ([]models.Group, int, error)
    Create(ctx context.Context, g *models.Group) error
    Update(ctx context.Context, g *models.Group) error
    Delete(ctx context.Context, id string) error
}

type UserGroupRepository interface {
    AddUser(ctx context.Context, groupID, userID string) error
    RemoveUser(ctx context.Context, groupID, userID string) error
    ListUsers(ctx context.Context, groupID string, limit, offset int) ([]models.User, int, error)
}

type GroupPolicyRepository interface {
    SetPolicy(ctx context.Context, groupID, policyID string) error
    GetPolicy(ctx context.Context, groupID string) (string, error)
    ClearPolicy(ctx context.Context, groupID string) error
}
