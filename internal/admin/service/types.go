package service

import (
	"context"

	"github.com/qmish/2FA/internal/dto"
)

type AdminService interface {
	ListUsers(ctx context.Context, req dto.AdminUserListRequest) (dto.AdminUserListResponse, error)
	CreateUser(ctx context.Context, req dto.AdminUserCreateRequest) (dto.AdminUserResponse, error)
	UpdateUser(ctx context.Context, id string, req dto.AdminUserUpdateRequest) (dto.AdminUserResponse, error)
	DeleteUser(ctx context.Context, id string) error
	ListPolicies(ctx context.Context, req dto.PageRequest) ([]dto.AdminPolicyDTO, dto.PageResponse, error)
	CreatePolicy(ctx context.Context, req dto.AdminPolicyCreateRequest) (dto.AdminPolicyDTO, error)
	UpdatePolicy(ctx context.Context, id string, req dto.AdminPolicyUpdateRequest) (dto.AdminPolicyDTO, error)
	DeletePolicy(ctx context.Context, id string) error
	ListRadiusClients(ctx context.Context, req dto.PageRequest) ([]dto.AdminRadiusClientDTO, dto.PageResponse, error)
	CreateRadiusClient(ctx context.Context, req dto.AdminRadiusClientCreateRequest) (dto.AdminRadiusClientDTO, error)
	UpdateRadiusClient(ctx context.Context, id string, req dto.AdminRadiusClientUpdateRequest) (dto.AdminRadiusClientDTO, error)
	DeleteRadiusClient(ctx context.Context, id string) error
	GetRolePermissions(ctx context.Context, role string) (dto.RolePermissionsResponse, error)
	SetRolePermissions(ctx context.Context, role string, req dto.RolePermissionsUpdateRequest) (dto.RolePermissionsResponse, error)
	ListGroups(ctx context.Context, req dto.PageRequest) (dto.AdminGroupListResponse, error)
	CreateGroup(ctx context.Context, req dto.AdminGroupCreateRequest) (dto.AdminGroupResponse, error)
	UpdateGroup(ctx context.Context, id string, req dto.AdminGroupUpdateRequest) (dto.AdminGroupResponse, error)
	DeleteGroup(ctx context.Context, id string) error
	AddGroupMember(ctx context.Context, groupID string, req dto.AdminGroupMemberRequest) error
	RemoveGroupMember(ctx context.Context, groupID string, req dto.AdminGroupMemberRequest) error
	ListGroupMembers(ctx context.Context, groupID string, page dto.PageRequest) (dto.AdminGroupMembersResponse, error)
	SetGroupPolicy(ctx context.Context, groupID string, req dto.AdminGroupPolicyRequest) error
	ClearGroupPolicy(ctx context.Context, groupID string) error
	ListAuditEvents(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error)
	ListLoginHistory(ctx context.Context, req dto.AdminLoginHistoryListRequest) (dto.AdminLoginHistoryListResponse, error)
	ListRadiusRequests(ctx context.Context, req dto.AdminRadiusRequestListRequest) (dto.AdminRadiusRequestListResponse, error)
	ListSessions(ctx context.Context, req dto.AdminSessionListRequest) (dto.AdminSessionListResponse, error)
	RevokeSession(ctx context.Context, actorUserID string, sessionID string, ip string) error
	RevokeUserSessions(ctx context.Context, actorUserID string, userID string, exceptSessionID string, ip string) error
	ListLockouts(ctx context.Context, req dto.AdminLockoutListRequest) (dto.AdminLockoutListResponse, error)
	ClearLockouts(ctx context.Context, actorUserID string, req dto.AdminLockoutClearRequest) error
	CreateInvite(ctx context.Context, req dto.AdminInviteCreateRequest) (dto.AdminInviteResponse, error)
}
