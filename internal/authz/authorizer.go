package authz

import (
    "context"
    "time"

    "github.com/qmish/2FA/internal/models"
    "github.com/qmish/2FA/internal/repository"
)

type Authorizer struct {
    audit     repository.AuditRepository
    rolePerms repository.RolePermissionRepository
}

func NewAuthorizer(audit repository.AuditRepository, rolePerms repository.RolePermissionRepository) *Authorizer {
    return &Authorizer{audit: audit, rolePerms: rolePerms}
}

func (a *Authorizer) HasPermission(ctx context.Context, userID string, role models.UserRole, perm models.Permission) bool {
    allowed := false
    if a.rolePerms != nil {
        perms, err := a.rolePerms.ListByRole(ctx, role)
        if err == nil && len(perms) > 0 {
            for _, p := range perms {
                if p == perm {
                    allowed = true
                    break
                }
            }
        } else if err == nil && len(perms) == 0 {
            allowed = roleHasPermission(role, perm)
        }
    } else {
        allowed = roleHasPermission(role, perm)
    }
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
