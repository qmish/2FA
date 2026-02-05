package handlers

import (
    "bytes"
    "context"
    "net/http"
    "net/http/httptest"
    "testing"

    adminsvc "github.com/qmish/2FA/internal/admin/service"
    "github.com/qmish/2FA/internal/api/middlewares"
    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/models"
)

func TestAdminListUsers(t *testing.T) {
    authz := fakeAuthorizer{}
    svc := &adminsvc.MockAdminService{
        ListUsersFunc: func(ctx context.Context, req dto.AdminUserListRequest) (dto.AdminUserListResponse, error) {
            if req.Page.Limit != 10 || req.Filter.Status != models.UserActive {
                t.Fatalf("unexpected request: %+v", req)
            }
            return dto.AdminUserListResponse{
                Items: []dto.AdminUserListItem{{ID: "u1", Username: "alice", Status: models.UserActive}},
                Page:  dto.PageResponse{Total: 1, Limit: 10, Offset: 0},
            }, nil
        },
        ListPoliciesFunc: func(ctx context.Context, req dto.PageRequest) ([]dto.AdminPolicyDTO, dto.PageResponse, error) {
            return nil, dto.PageResponse{}, nil
        },
        ListRadiusClientsFunc: func(ctx context.Context, req dto.PageRequest) ([]dto.AdminRadiusClientDTO, dto.PageResponse, error) {
            return nil, dto.PageResponse{}, nil
        },
        ListAuditEventsFunc: func(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error) {
            return dto.AdminAuditListResponse{}, nil
        },
        ListLoginHistoryFunc: func(ctx context.Context, req dto.AdminLoginHistoryListRequest) (dto.AdminLoginHistoryListResponse, error) {
            return dto.AdminLoginHistoryListResponse{}, nil
        },
        ListRadiusRequestsFunc: func(ctx context.Context, req dto.AdminRadiusRequestListRequest) (dto.AdminRadiusRequestListResponse, error) {
            return dto.AdminRadiusRequestListResponse{}, nil
        },
    }

    handler := NewAdminHandler(svc, authz)
    req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users?limit=10&status=active", nil)
    req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
    rec := httptest.NewRecorder()

    handler.ListUsers(rec, req)

    if rec.Code != http.StatusOK {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestAdminCreateUser(t *testing.T) {
    authz := fakeAuthorizer{}
    svc := &adminsvc.MockAdminService{
        CreateUserFunc: func(ctx context.Context, req dto.AdminUserCreateRequest) (dto.AdminUserResponse, error) {
            return dto.AdminUserResponse{ID: "u1", Username: req.Username, Role: req.Role}, nil
        },
        ListUsersFunc: func(ctx context.Context, req dto.AdminUserListRequest) (dto.AdminUserListResponse, error) {
            return dto.AdminUserListResponse{}, nil
        },
        ListPoliciesFunc: func(ctx context.Context, req dto.PageRequest) ([]dto.AdminPolicyDTO, dto.PageResponse, error) {
            return nil, dto.PageResponse{}, nil
        },
        ListRadiusClientsFunc: func(ctx context.Context, req dto.PageRequest) ([]dto.AdminRadiusClientDTO, dto.PageResponse, error) {
            return nil, dto.PageResponse{}, nil
        },
        ListAuditEventsFunc: func(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error) {
            return dto.AdminAuditListResponse{}, nil
        },
        ListLoginHistoryFunc: func(ctx context.Context, req dto.AdminLoginHistoryListRequest) (dto.AdminLoginHistoryListResponse, error) {
            return dto.AdminLoginHistoryListResponse{}, nil
        },
        ListRadiusRequestsFunc: func(ctx context.Context, req dto.AdminRadiusRequestListRequest) (dto.AdminRadiusRequestListResponse, error) {
            return dto.AdminRadiusRequestListResponse{}, nil
        },
        UpdateUserFunc: func(ctx context.Context, id string, req dto.AdminUserUpdateRequest) (dto.AdminUserResponse, error) {
            return dto.AdminUserResponse{}, nil
        },
        DeleteUserFunc: func(ctx context.Context, id string) error { return nil },
        CreatePolicyFunc: func(ctx context.Context, req dto.AdminPolicyCreateRequest) (dto.AdminPolicyDTO, error) {
            return dto.AdminPolicyDTO{}, nil
        },
        UpdatePolicyFunc: func(ctx context.Context, id string, req dto.AdminPolicyUpdateRequest) (dto.AdminPolicyDTO, error) {
            return dto.AdminPolicyDTO{}, nil
        },
        DeletePolicyFunc: func(ctx context.Context, id string) error { return nil },
        CreateRadiusClientFunc: func(ctx context.Context, req dto.AdminRadiusClientCreateRequest) (dto.AdminRadiusClientDTO, error) {
            return dto.AdminRadiusClientDTO{}, nil
        },
        UpdateRadiusClientFunc: func(ctx context.Context, id string, req dto.AdminRadiusClientUpdateRequest) (dto.AdminRadiusClientDTO, error) {
            return dto.AdminRadiusClientDTO{}, nil
        },
        DeleteRadiusClientFunc: func(ctx context.Context, id string) error { return nil },
        GetRolePermissionsFunc: func(ctx context.Context, role string) (dto.RolePermissionsResponse, error) {
            return dto.RolePermissionsResponse{}, nil
        },
        SetRolePermissionsFunc: func(ctx context.Context, role string, req dto.RolePermissionsUpdateRequest) (dto.RolePermissionsResponse, error) {
            return dto.RolePermissionsResponse{}, nil
        },
    }

    handler := NewAdminHandler(svc, authz)
    body := bytes.NewBufferString(`{"username":"bob","password":"secret","status":"active","role":"user"}`)
    req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/create", body)
    req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
    rec := httptest.NewRecorder()

    handler.CreateUser(rec, req)
    if rec.Code != http.StatusCreated {
        t.Fatalf("status=%d", rec.Code)
    }
}

func TestAdminCreateGroup(t *testing.T) {
    authz := fakeAuthorizer{}
    svc := &adminsvc.MockAdminService{
        CreateGroupFunc: func(ctx context.Context, req dto.AdminGroupCreateRequest) (dto.AdminGroupResponse, error) {
            return dto.AdminGroupResponse{ID: "g1", Name: req.Name}, nil
        },
        ListUsersFunc: func(ctx context.Context, req dto.AdminUserListRequest) (dto.AdminUserListResponse, error) {
            return dto.AdminUserListResponse{}, nil
        },
        CreateUserFunc: func(ctx context.Context, req dto.AdminUserCreateRequest) (dto.AdminUserResponse, error) {
            return dto.AdminUserResponse{}, nil
        },
        UpdateUserFunc: func(ctx context.Context, id string, req dto.AdminUserUpdateRequest) (dto.AdminUserResponse, error) {
            return dto.AdminUserResponse{}, nil
        },
        DeleteUserFunc: func(ctx context.Context, id string) error { return nil },
        ListPoliciesFunc: func(ctx context.Context, req dto.PageRequest) ([]dto.AdminPolicyDTO, dto.PageResponse, error) {
            return nil, dto.PageResponse{}, nil
        },
        CreatePolicyFunc: func(ctx context.Context, req dto.AdminPolicyCreateRequest) (dto.AdminPolicyDTO, error) {
            return dto.AdminPolicyDTO{}, nil
        },
        UpdatePolicyFunc: func(ctx context.Context, id string, req dto.AdminPolicyUpdateRequest) (dto.AdminPolicyDTO, error) {
            return dto.AdminPolicyDTO{}, nil
        },
        DeletePolicyFunc: func(ctx context.Context, id string) error { return nil },
        ListRadiusClientsFunc: func(ctx context.Context, req dto.PageRequest) ([]dto.AdminRadiusClientDTO, dto.PageResponse, error) {
            return nil, dto.PageResponse{}, nil
        },
        CreateRadiusClientFunc: func(ctx context.Context, req dto.AdminRadiusClientCreateRequest) (dto.AdminRadiusClientDTO, error) {
            return dto.AdminRadiusClientDTO{}, nil
        },
        UpdateRadiusClientFunc: func(ctx context.Context, id string, req dto.AdminRadiusClientUpdateRequest) (dto.AdminRadiusClientDTO, error) {
            return dto.AdminRadiusClientDTO{}, nil
        },
        DeleteRadiusClientFunc: func(ctx context.Context, id string) error { return nil },
        GetRolePermissionsFunc: func(ctx context.Context, role string) (dto.RolePermissionsResponse, error) {
            return dto.RolePermissionsResponse{}, nil
        },
        SetRolePermissionsFunc: func(ctx context.Context, role string, req dto.RolePermissionsUpdateRequest) (dto.RolePermissionsResponse, error) {
            return dto.RolePermissionsResponse{}, nil
        },
        ListAuditEventsFunc: func(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error) {
            return dto.AdminAuditListResponse{}, nil
        },
        ListLoginHistoryFunc: func(ctx context.Context, req dto.AdminLoginHistoryListRequest) (dto.AdminLoginHistoryListResponse, error) {
            return dto.AdminLoginHistoryListResponse{}, nil
        },
        ListRadiusRequestsFunc: func(ctx context.Context, req dto.AdminRadiusRequestListRequest) (dto.AdminRadiusRequestListResponse, error) {
            return dto.AdminRadiusRequestListResponse{}, nil
        },
        AddGroupMemberFunc: func(ctx context.Context, groupID string, req dto.AdminGroupMemberRequest) error { return nil },
        RemoveGroupMemberFunc: func(ctx context.Context, groupID string, req dto.AdminGroupMemberRequest) error { return nil },
        ListGroupMembersFunc: func(ctx context.Context, groupID string, page dto.PageRequest) (dto.AdminGroupMembersResponse, error) {
            return dto.AdminGroupMembersResponse{}, nil
        },
        SetGroupPolicyFunc: func(ctx context.Context, groupID string, req dto.AdminGroupPolicyRequest) error { return nil },
        ClearGroupPolicyFunc: func(ctx context.Context, groupID string) error { return nil },
        UpdateGroupFunc: func(ctx context.Context, id string, req dto.AdminGroupUpdateRequest) (dto.AdminGroupResponse, error) {
            return dto.AdminGroupResponse{}, nil
        },
        DeleteGroupFunc: func(ctx context.Context, id string) error { return nil },
        ListGroupsFunc: func(ctx context.Context, req dto.PageRequest) (dto.AdminGroupListResponse, error) {
            return dto.AdminGroupListResponse{}, nil
        },
    }

    handler := NewAdminHandler(svc, authz)
    body := bytes.NewBufferString(`{"name":"ops","description":"ops team"}`)
    req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/groups/create", body)
    req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
    rec := httptest.NewRecorder()

    handler.CreateGroup(rec, req)
    if rec.Code != http.StatusCreated {
        t.Fatalf("status=%d", rec.Code)
    }
}

type fakeAuthorizer struct{}

func (fakeAuthorizer) HasPermission(ctx context.Context, userID string, role models.UserRole, perm models.Permission) bool {
    return true
}
