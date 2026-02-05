package authz

import (
    "context"
    "time"

    "github.com/qmish/2FA/internal/models"
    "github.com/qmish/2FA/internal/repository"
)

type Authorizer struct {
    audit repository.AuditRepository
}

func NewAuthorizer(audit repository.AuditRepository) *Authorizer {
    return &Authorizer{audit: audit}
}

func (a *Authorizer) HasPermission(ctx context.Context, userID string, role models.UserRole, perm models.Permission) bool {
    allowed := roleHasPermission(role, perm)
    if a.audit != nil {
        _ = a.audit.Create(ctx, &models.AuditEvent{
            ID:         "",
            ActorUserID: userID,
            Action:     models.AuditAuthorize,
            EntityType: models.AuditEntityPermission,
            EntityID:   string(perm),
            Payload:    "",
            IP:         "",
            CreatedAt:  time.Now(),
        })
    }
    return allowed
}

func roleHasPermission(role models.UserRole, perm models.Permission) bool {
    if role == models.RoleAdmin {
        return true
    }
    switch perm {
    case models.PermissionAdminUsersRead,
        models.PermissionAdminPoliciesRead,
        models.PermissionAdminRadiusClientsRead,
        models.PermissionAdminAuditRead,
        models.PermissionAdminLoginsRead,
        models.PermissionAdminRadiusRequestsRead:
        return false
    default:
        return false
    }
}
