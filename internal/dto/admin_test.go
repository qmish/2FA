package dto

import (
    "encoding/json"
    "strings"
    "testing"

    "github.com/qmish/2FA/internal/models"
)

func TestAdminUserListItemJSON(t *testing.T) {
    item := AdminUserListItem{
        ID:       "u1",
        Username: "alice",
        Email:    "a@example.com",
        Phone:    "+79990000000",
        Status:   models.UserActive,
        Role:     models.RoleAdmin,
    }

    data, err := json.Marshal(item)
    if err != nil {
        t.Fatalf("marshal error: %v", err)
    }

    got := string(data)
    wantFragments := []string{
        "\"id\":\"u1\"",
        "\"username\":\"alice\"",
        "\"email\":\"a@example.com\"",
        "\"phone\":\"+79990000000\"",
        "\"status\":\"active\"",
        "\"role\":\"admin\"",
    }
    for _, frag := range wantFragments {
        if !strings.Contains(got, frag) {
            t.Fatalf("missing json fragment %q in %s", frag, got)
        }
    }
}

func TestAdminUserCreateJSON(t *testing.T) {
    req := AdminUserCreateRequest{
        Username: "bob",
        Email:    "b@example.com",
        Phone:    "+70000000000",
        Status:   models.UserActive,
        Role:     models.RoleUser,
        Password: "secret",
    }
    data, err := json.Marshal(req)
    if err != nil {
        t.Fatalf("marshal error: %v", err)
    }
    got := string(data)
    wantFragments := []string{
        "\"username\":\"bob\"",
        "\"email\":\"b@example.com\"",
        "\"phone\":\"+70000000000\"",
        "\"status\":\"active\"",
        "\"role\":\"user\"",
        "\"password\":\"secret\"",
    }
    for _, frag := range wantFragments {
        if !strings.Contains(got, frag) {
            t.Fatalf("missing json fragment %q in %s", frag, got)
        }
    }
}

func TestRolePermissionsUpdateJSON(t *testing.T) {
    req := RolePermissionsUpdateRequest{
        Permissions: []models.Permission{models.PermissionAdminUsersRead},
    }
    data, err := json.Marshal(req)
    if err != nil {
        t.Fatalf("marshal error: %v", err)
    }
    got := string(data)
    if !strings.Contains(got, "\"permissions\"") {
        t.Fatalf("missing permissions in json: %s", got)
    }
}
