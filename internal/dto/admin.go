package dto

import (
    "time"

    "github.com/qmish/2FA/internal/models"
)

type AdminUserListItem struct {
    ID       string            `json:"id"`
    Username string            `json:"username"`
    Email    string            `json:"email"`
    Phone    string            `json:"phone"`
    Status   models.UserStatus `json:"status"`
    Role     models.UserRole   `json:"role"`
}

type AdminPolicyDTO struct {
    ID       string             `json:"id"`
    Name     string             `json:"name"`
    Priority int                `json:"priority"`
    Status   models.PolicyStatus `json:"status"`
    Rules    []PolicyRuleDTO    `json:"rules"`
}

type PolicyRuleDTO struct {
    ID    string               `json:"id"`
    Type  models.PolicyRuleType `json:"type"`
    Value string               `json:"value"`
}

type AdminRadiusClientDTO struct {
    ID      string `json:"id"`
    Name    string `json:"name"`
    IP      string `json:"ip"`
    Enabled bool   `json:"enabled"`
}

type AdminAuditEventDTO struct {
    ID          string              `json:"id"`
    ActorUserID string              `json:"actor_user_id"`
    Action      models.AuditAction  `json:"action"`
    EntityType  models.AuditEntityType `json:"entity_type"`
    EntityID    string              `json:"entity_id"`
    Payload     string              `json:"payload"`
    IP          string              `json:"ip"`
    CreatedAt   time.Time           `json:"created_at"`
}

type LoginHistoryDTO struct {
    ID        string            `json:"id"`
    UserID    string            `json:"user_id"`
    Channel   models.AuthChannel `json:"channel"`
    Result    models.AuthResult  `json:"result"`
    IP        string            `json:"ip"`
    DeviceID  string            `json:"device_id"`
    CreatedAt time.Time         `json:"created_at"`
}

type RadiusRequestDTO struct {
    ID        string             `json:"id"`
    ClientID  string             `json:"client_id"`
    Username  string             `json:"username"`
    NASIP     string             `json:"nas_ip"`
    Result    models.RadiusResult `json:"result"`
    CreatedAt time.Time          `json:"created_at"`
}

type AdminSessionDTO struct {
    ID        string     `json:"id"`
    UserID    string     `json:"user_id"`
    IP        string     `json:"ip"`
    UserAgent string     `json:"user_agent"`
    CreatedAt time.Time  `json:"created_at"`
    ExpiresAt time.Time  `json:"expires_at"`
    LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
    RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type PageRequest struct {
    Limit     int    `json:"limit"`
    Offset    int    `json:"offset"`
    SortBy    string `json:"sort_by"`
    SortOrder string `json:"sort_order"`
}

type PageResponse struct {
    Total  int `json:"total"`
    Limit  int `json:"limit"`
    Offset int `json:"offset"`
}

type AdminUserFilter struct {
    Query   string            `json:"query"`
    Status  models.UserStatus `json:"status"`
    GroupID string            `json:"group_id"`
}

type AdminPolicyFilter struct {
    Status models.PolicyStatus `json:"status"`
}

type AdminAuditFilter struct {
    ActorUserID string               `json:"actor_user_id"`
    EntityType  models.AuditEntityType `json:"entity_type"`
    Action      models.AuditAction   `json:"action"`
    EntityID    string               `json:"entity_id"`
    IP          string               `json:"ip"`
    Payload     string               `json:"payload"`
    From        time.Time            `json:"from"`
    To          time.Time            `json:"to"`
}

type AdminLoginHistoryFilter struct {
    UserID  string            `json:"user_id"`
    Channel models.AuthChannel `json:"channel"`
    Result  models.AuthResult  `json:"result"`
    IP      string            `json:"ip"`
    DeviceID string           `json:"device_id"`
    From    time.Time         `json:"from"`
    To      time.Time         `json:"to"`
}

type AdminRadiusRequestFilter struct {
    ClientID string             `json:"client_id"`
    Username string             `json:"username"`
    Result   models.RadiusResult `json:"result"`
    From     time.Time          `json:"from"`
    To       time.Time          `json:"to"`
}

type AdminSessionFilter struct {
    UserID string `json:"user_id"`
    ActiveOnly bool `json:"active_only"`
    IP string `json:"ip"`
    UserAgent string `json:"user_agent"`
}

type AdminUserListRequest struct {
    Page   PageRequest    `json:"page"`
    Filter AdminUserFilter `json:"filter"`
}

type AdminUserListResponse struct {
    Items []AdminUserListItem `json:"items"`
    Page  PageResponse        `json:"page"`
}

type AdminPolicyListResponse struct {
    Items []AdminPolicyDTO `json:"items"`
    Page  PageResponse     `json:"page"`
}

type AdminRadiusClientListResponse struct {
    Items []AdminRadiusClientDTO `json:"items"`
    Page  PageResponse           `json:"page"`
}

type AdminAuditListRequest struct {
    Page   PageRequest   `json:"page"`
    Filter AdminAuditFilter `json:"filter"`
}

type AdminAuditListResponse struct {
    Items []AdminAuditEventDTO `json:"items"`
    Page  PageResponse         `json:"page"`
}

type AdminLoginHistoryListRequest struct {
    Page   PageRequest         `json:"page"`
    Filter AdminLoginHistoryFilter `json:"filter"`
}

type AdminLoginHistoryListResponse struct {
    Items []LoginHistoryDTO `json:"items"`
    Page  PageResponse      `json:"page"`
}

type AdminRadiusRequestListRequest struct {
    Page   PageRequest          `json:"page"`
    Filter AdminRadiusRequestFilter `json:"filter"`
}

type AdminSessionListRequest struct {
    Page   PageRequest       `json:"page"`
    Filter AdminSessionFilter `json:"filter"`
}

type AdminRadiusRequestListResponse struct {
    Items []RadiusRequestDTO `json:"items"`
    Page  PageResponse       `json:"page"`
}

type AdminSessionListResponse struct {
    Items []AdminSessionDTO `json:"items"`
    Page  PageResponse      `json:"page"`
}

type AdminSessionRevokeRequest struct {
    SessionID string `json:"session_id"`
}

type AdminUserSessionsRevokeRequest struct {
    UserID          string `json:"user_id"`
    ExceptSessionID string `json:"except_session_id"`
}

type AdminLockoutDTO struct {
    ID        string     `json:"id"`
    UserID    string     `json:"user_id"`
    IP        string     `json:"ip"`
    Reason    string     `json:"reason"`
    ExpiresAt time.Time  `json:"expires_at"`
    CreatedAt time.Time  `json:"created_at"`
}

type AdminLockoutFilter struct {
    UserID string `json:"user_id"`
    IP     string `json:"ip"`
    Reason string `json:"reason"`
    ActiveOnly bool `json:"active_only"`
}

type AdminLockoutListRequest struct {
    Page   PageRequest      `json:"page"`
    Filter AdminLockoutFilter `json:"filter"`
}

type AdminLockoutListResponse struct {
    Items []AdminLockoutDTO `json:"items"`
    Page  PageResponse      `json:"page"`
}

type AdminLockoutClearRequest struct {
    UserID string `json:"user_id"`
    IP     string `json:"ip"`
    Reason string `json:"reason"`
}
