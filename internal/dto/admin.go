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
    From        time.Time            `json:"from"`
    To          time.Time            `json:"to"`
}

type AdminLoginHistoryFilter struct {
    UserID  string            `json:"user_id"`
    Channel models.AuthChannel `json:"channel"`
    Result  models.AuthResult  `json:"result"`
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

type AdminRadiusRequestListResponse struct {
    Items []RadiusRequestDTO `json:"items"`
    Page  PageResponse       `json:"page"`
}
