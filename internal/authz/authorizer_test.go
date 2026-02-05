package authz

import (
    "context"
    "testing"

    "github.com/qmish/2FA/internal/models"
)

func TestAuthorizerAdminAllows(t *testing.T) {
    auth := NewAuthorizer(nil)
    if !auth.HasPermission(context.Background(), "u1", models.RoleAdmin, models.PermissionAdminUsersRead) {
        t.Fatalf("admin should be allowed")
    }
}

func TestAuthorizerUserDenies(t *testing.T) {
    auth := NewAuthorizer(nil)
    if auth.HasPermission(context.Background(), "u1", models.RoleUser, models.PermissionAdminUsersRead) {
        t.Fatalf("user should be denied")
    }
}
