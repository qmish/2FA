package service

import (
    "context"
    "errors"

    "github.com/qmish/2FA/internal/dto"
)

var ErrNotImplemented = errors.New("not implemented")

type StubService struct{}

func (s StubService) ListUsers(ctx context.Context, req dto.AdminUserListRequest) (dto.AdminUserListResponse, error) {
    _ = ctx
    _ = req
    return dto.AdminUserListResponse{}, ErrNotImplemented
}

func (s StubService) CreateUser(ctx context.Context, req dto.AdminUserCreateRequest) (dto.AdminUserResponse, error) {
    _ = ctx
    _ = req
    return dto.AdminUserResponse{}, ErrNotImplemented
}

func (s StubService) UpdateUser(ctx context.Context, id string, req dto.AdminUserUpdateRequest) (dto.AdminUserResponse, error) {
    _ = ctx
    _ = id
    _ = req
    return dto.AdminUserResponse{}, ErrNotImplemented
}

func (s StubService) DeleteUser(ctx context.Context, id string) error {
    _ = ctx
    _ = id
    return ErrNotImplemented
}

func (s StubService) ListPolicies(ctx context.Context, req dto.PageRequest) ([]dto.AdminPolicyDTO, dto.PageResponse, error) {
    _ = ctx
    _ = req
    return nil, dto.PageResponse{}, ErrNotImplemented
}

func (s StubService) CreatePolicy(ctx context.Context, req dto.AdminPolicyCreateRequest) (dto.AdminPolicyDTO, error) {
    _ = ctx
    _ = req
    return dto.AdminPolicyDTO{}, ErrNotImplemented
}

func (s StubService) UpdatePolicy(ctx context.Context, id string, req dto.AdminPolicyUpdateRequest) (dto.AdminPolicyDTO, error) {
    _ = ctx
    _ = id
    _ = req
    return dto.AdminPolicyDTO{}, ErrNotImplemented
}

func (s StubService) DeletePolicy(ctx context.Context, id string) error {
    _ = ctx
    _ = id
    return ErrNotImplemented
}

func (s StubService) ListRadiusClients(ctx context.Context, req dto.PageRequest) ([]dto.AdminRadiusClientDTO, dto.PageResponse, error) {
    _ = ctx
    _ = req
    return nil, dto.PageResponse{}, ErrNotImplemented
}

func (s StubService) CreateRadiusClient(ctx context.Context, req dto.AdminRadiusClientCreateRequest) (dto.AdminRadiusClientDTO, error) {
    _ = ctx
    _ = req
    return dto.AdminRadiusClientDTO{}, ErrNotImplemented
}

func (s StubService) UpdateRadiusClient(ctx context.Context, id string, req dto.AdminRadiusClientUpdateRequest) (dto.AdminRadiusClientDTO, error) {
    _ = ctx
    _ = id
    _ = req
    return dto.AdminRadiusClientDTO{}, ErrNotImplemented
}

func (s StubService) DeleteRadiusClient(ctx context.Context, id string) error {
    _ = ctx
    _ = id
    return ErrNotImplemented
}

func (s StubService) GetRolePermissions(ctx context.Context, role string) (dto.RolePermissionsResponse, error) {
    _ = ctx
    _ = role
    return dto.RolePermissionsResponse{}, ErrNotImplemented
}

func (s StubService) SetRolePermissions(ctx context.Context, role string, req dto.RolePermissionsUpdateRequest) (dto.RolePermissionsResponse, error) {
    _ = ctx
    _ = role
    _ = req
    return dto.RolePermissionsResponse{}, ErrNotImplemented
}

func (s StubService) ListAuditEvents(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error) {
    _ = ctx
    _ = req
    return dto.AdminAuditListResponse{}, ErrNotImplemented
}

func (s StubService) ListLoginHistory(ctx context.Context, req dto.AdminLoginHistoryListRequest) (dto.AdminLoginHistoryListResponse, error) {
    _ = ctx
    _ = req
    return dto.AdminLoginHistoryListResponse{}, ErrNotImplemented
}

func (s StubService) ListRadiusRequests(ctx context.Context, req dto.AdminRadiusRequestListRequest) (dto.AdminRadiusRequestListResponse, error) {
    _ = ctx
    _ = req
    return dto.AdminRadiusRequestListResponse{}, ErrNotImplemented
}
