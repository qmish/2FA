package service

import (
    "context"

    "github.com/qmish/2FA/internal/dto"
)

type MockAdminService struct {
    ListUsersFunc          func(ctx context.Context, req dto.AdminUserListRequest) (dto.AdminUserListResponse, error)
    CreateUserFunc         func(ctx context.Context, req dto.AdminUserCreateRequest) (dto.AdminUserResponse, error)
    UpdateUserFunc         func(ctx context.Context, id string, req dto.AdminUserUpdateRequest) (dto.AdminUserResponse, error)
    DeleteUserFunc         func(ctx context.Context, id string) error
    ListPoliciesFunc       func(ctx context.Context, req dto.PageRequest) ([]dto.AdminPolicyDTO, dto.PageResponse, error)
    CreatePolicyFunc       func(ctx context.Context, req dto.AdminPolicyCreateRequest) (dto.AdminPolicyDTO, error)
    UpdatePolicyFunc       func(ctx context.Context, id string, req dto.AdminPolicyUpdateRequest) (dto.AdminPolicyDTO, error)
    DeletePolicyFunc       func(ctx context.Context, id string) error
    ListRadiusClientsFunc  func(ctx context.Context, req dto.PageRequest) ([]dto.AdminRadiusClientDTO, dto.PageResponse, error)
    CreateRadiusClientFunc func(ctx context.Context, req dto.AdminRadiusClientCreateRequest) (dto.AdminRadiusClientDTO, error)
    UpdateRadiusClientFunc func(ctx context.Context, id string, req dto.AdminRadiusClientUpdateRequest) (dto.AdminRadiusClientDTO, error)
    DeleteRadiusClientFunc func(ctx context.Context, id string) error
    GetRolePermissionsFunc func(ctx context.Context, role string) (dto.RolePermissionsResponse, error)
    SetRolePermissionsFunc func(ctx context.Context, role string, req dto.RolePermissionsUpdateRequest) (dto.RolePermissionsResponse, error)
    ListAuditEventsFunc    func(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error)
    ListLoginHistoryFunc   func(ctx context.Context, req dto.AdminLoginHistoryListRequest) (dto.AdminLoginHistoryListResponse, error)
    ListRadiusRequestsFunc func(ctx context.Context, req dto.AdminRadiusRequestListRequest) (dto.AdminRadiusRequestListResponse, error)
}

func (m *MockAdminService) ListUsers(ctx context.Context, req dto.AdminUserListRequest) (dto.AdminUserListResponse, error) {
    return m.ListUsersFunc(ctx, req)
}

func (m *MockAdminService) CreateUser(ctx context.Context, req dto.AdminUserCreateRequest) (dto.AdminUserResponse, error) {
    return m.CreateUserFunc(ctx, req)
}

func (m *MockAdminService) UpdateUser(ctx context.Context, id string, req dto.AdminUserUpdateRequest) (dto.AdminUserResponse, error) {
    return m.UpdateUserFunc(ctx, id, req)
}

func (m *MockAdminService) DeleteUser(ctx context.Context, id string) error {
    return m.DeleteUserFunc(ctx, id)
}

func (m *MockAdminService) ListPolicies(ctx context.Context, req dto.PageRequest) ([]dto.AdminPolicyDTO, dto.PageResponse, error) {
    return m.ListPoliciesFunc(ctx, req)
}

func (m *MockAdminService) CreatePolicy(ctx context.Context, req dto.AdminPolicyCreateRequest) (dto.AdminPolicyDTO, error) {
    return m.CreatePolicyFunc(ctx, req)
}

func (m *MockAdminService) UpdatePolicy(ctx context.Context, id string, req dto.AdminPolicyUpdateRequest) (dto.AdminPolicyDTO, error) {
    return m.UpdatePolicyFunc(ctx, id, req)
}

func (m *MockAdminService) DeletePolicy(ctx context.Context, id string) error {
    return m.DeletePolicyFunc(ctx, id)
}

func (m *MockAdminService) ListRadiusClients(ctx context.Context, req dto.PageRequest) ([]dto.AdminRadiusClientDTO, dto.PageResponse, error) {
    return m.ListRadiusClientsFunc(ctx, req)
}

func (m *MockAdminService) CreateRadiusClient(ctx context.Context, req dto.AdminRadiusClientCreateRequest) (dto.AdminRadiusClientDTO, error) {
    return m.CreateRadiusClientFunc(ctx, req)
}

func (m *MockAdminService) UpdateRadiusClient(ctx context.Context, id string, req dto.AdminRadiusClientUpdateRequest) (dto.AdminRadiusClientDTO, error) {
    return m.UpdateRadiusClientFunc(ctx, id, req)
}

func (m *MockAdminService) DeleteRadiusClient(ctx context.Context, id string) error {
    return m.DeleteRadiusClientFunc(ctx, id)
}

func (m *MockAdminService) GetRolePermissions(ctx context.Context, role string) (dto.RolePermissionsResponse, error) {
    return m.GetRolePermissionsFunc(ctx, role)
}

func (m *MockAdminService) SetRolePermissions(ctx context.Context, role string, req dto.RolePermissionsUpdateRequest) (dto.RolePermissionsResponse, error) {
    return m.SetRolePermissionsFunc(ctx, role, req)
}

func (m *MockAdminService) ListAuditEvents(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error) {
    return m.ListAuditEventsFunc(ctx, req)
}

func (m *MockAdminService) ListLoginHistory(ctx context.Context, req dto.AdminLoginHistoryListRequest) (dto.AdminLoginHistoryListResponse, error) {
    return m.ListLoginHistoryFunc(ctx, req)
}

func (m *MockAdminService) ListRadiusRequests(ctx context.Context, req dto.AdminRadiusRequestListRequest) (dto.AdminRadiusRequestListResponse, error) {
    return m.ListRadiusRequestsFunc(ctx, req)
}
