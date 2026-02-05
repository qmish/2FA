package service

import (
    "context"

    "github.com/qmish/2FA/internal/dto"
)

type MockAdminService struct {
    ListUsersFunc          func(ctx context.Context, req dto.AdminUserListRequest) (dto.AdminUserListResponse, error)
    ListPoliciesFunc       func(ctx context.Context, req dto.PageRequest) ([]dto.AdminPolicyDTO, dto.PageResponse, error)
    ListRadiusClientsFunc  func(ctx context.Context, req dto.PageRequest) ([]dto.AdminRadiusClientDTO, dto.PageResponse, error)
    ListAuditEventsFunc    func(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error)
    ListLoginHistoryFunc   func(ctx context.Context, req dto.AdminLoginHistoryListRequest) (dto.AdminLoginHistoryListResponse, error)
    ListRadiusRequestsFunc func(ctx context.Context, req dto.AdminRadiusRequestListRequest) (dto.AdminRadiusRequestListResponse, error)
}

func (m *MockAdminService) ListUsers(ctx context.Context, req dto.AdminUserListRequest) (dto.AdminUserListResponse, error) {
    return m.ListUsersFunc(ctx, req)
}

func (m *MockAdminService) ListPolicies(ctx context.Context, req dto.PageRequest) ([]dto.AdminPolicyDTO, dto.PageResponse, error) {
    return m.ListPoliciesFunc(ctx, req)
}

func (m *MockAdminService) ListRadiusClients(ctx context.Context, req dto.PageRequest) ([]dto.AdminRadiusClientDTO, dto.PageResponse, error) {
    return m.ListRadiusClientsFunc(ctx, req)
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
