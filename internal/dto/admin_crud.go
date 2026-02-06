package dto

import "github.com/qmish/2FA/internal/models"

type AdminUserCreateRequest struct {
	Username string            `json:"username"`
	Email    string            `json:"email"`
	Phone    string            `json:"phone"`
	Status   models.UserStatus `json:"status"`
	Role     models.UserRole   `json:"role"`
	Password string            `json:"password"`
}

type AdminInviteCreateRequest struct {
	Email      string          `json:"email"`
	Phone      string          `json:"phone"`
	Role       models.UserRole `json:"role"`
	TTLMinutes int             `json:"ttl_minutes"`
}

type AdminInviteResponse struct {
	ID        string          `json:"id"`
	Token     string          `json:"token"`
	Email     string          `json:"email"`
	Phone     string          `json:"phone"`
	Role      models.UserRole `json:"role"`
	ExpiresAt int64           `json:"expires_at"`
}

type AdminUserUpdateRequest struct {
	Email  string            `json:"email"`
	Phone  string            `json:"phone"`
	Status models.UserStatus `json:"status"`
	Role   models.UserRole   `json:"role"`
}

type AdminUserResponse struct {
	ID       string            `json:"id"`
	Username string            `json:"username"`
	Email    string            `json:"email"`
	Phone    string            `json:"phone"`
	Status   models.UserStatus `json:"status"`
	Role     models.UserRole   `json:"role"`
}

type AdminPolicyCreateRequest struct {
	Name     string              `json:"name"`
	Priority int                 `json:"priority"`
	Status   models.PolicyStatus `json:"status"`
	Rules    []PolicyRuleDTO     `json:"rules"`
}

type AdminPolicyUpdateRequest struct {
	Name     string              `json:"name"`
	Priority int                 `json:"priority"`
	Status   models.PolicyStatus `json:"status"`
	Rules    []PolicyRuleDTO     `json:"rules"`
}

type AdminRadiusClientCreateRequest struct {
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Secret  string `json:"secret"`
	Enabled bool   `json:"enabled"`
}

type AdminRadiusClientUpdateRequest struct {
	Name    string `json:"name"`
	Secret  string `json:"secret"`
	Enabled bool   `json:"enabled"`
}

type RolePermissionsResponse struct {
	Role        models.UserRole     `json:"role"`
	Permissions []models.Permission `json:"permissions"`
}

type RolePermissionsUpdateRequest struct {
	Permissions []models.Permission `json:"permissions"`
}

type AdminGroupCreateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type AdminGroupUpdateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type AdminGroupResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type AdminGroupListResponse struct {
	Items []AdminGroupResponse `json:"items"`
	Page  PageResponse         `json:"page"`
}

type AdminGroupMemberRequest struct {
	UserID string `json:"user_id"`
}

type AdminGroupMembersResponse struct {
	Items []AdminUserListItem `json:"items"`
	Page  PageResponse        `json:"page"`
}

type AdminGroupPolicyRequest struct {
	PolicyID string `json:"policy_id"`
}
