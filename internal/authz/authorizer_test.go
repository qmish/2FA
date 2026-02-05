package authz

import (
    "context"
    "testing"

    "github.com/qmish/2FA/internal/models"
)

func TestAuthorizerAdminAllows(t *testing.T) {
    auth := NewAuthorizer(nil, nil)
    if !auth.HasPermission(context.Background(), "u1", models.RoleAdmin, models.PermissionAdminUsersRead) {
        t.Fatalf("admin should be allowed")
    }
}

func TestAuthorizerUserDenies(t *testing.T) {
    auth := NewAuthorizer(nil, nil)
    if auth.HasPermission(context.Background(), "u1", models.RoleUser, models.PermissionAdminUsersRead) {
        t.Fatalf("user should be denied")
    }
}

func TestAuthorizerRolePermsFromRepo(t *testing.T) {
    repo := fakeRolePerms{perms: []models.Permission{models.PermissionAdminUsersRead}}
    auth := NewAuthorizer(nil, repo)
    if !auth.HasPermission(context.Background(), "u1", models.RoleUser, models.PermissionAdminUsersRead) {
        t.Fatalf("expected permission from repo")
    }
}

type fakeRolePerms struct {
    perms []models.Permission
}

func (f fakeRolePerms) ListByRole(ctx context.Context, role models.UserRole) ([]models.Permission, error) {
    return f.perms, nil
}
func (f fakeRolePerms) SetRolePermissions(ctx context.Context, role models.UserRole, perms []models.Permission) error {
    return nil
}
