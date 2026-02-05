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

func (s StubService) ListPolicies(ctx context.Context, req dto.PageRequest) ([]dto.AdminPolicyDTO, dto.PageResponse, error) {
    _ = ctx
    _ = req
    return nil, dto.PageResponse{}, ErrNotImplemented
}

func (s StubService) ListRadiusClients(ctx context.Context, req dto.PageRequest) ([]dto.AdminRadiusClientDTO, dto.PageResponse, error) {
    _ = ctx
    _ = req
    return nil, dto.PageResponse{}, ErrNotImplemented
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
