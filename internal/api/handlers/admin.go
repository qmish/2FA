package handlers

import (
    "context"
    "encoding/json"
    "net/http"
    "strconv"
    "time"

    adminsvc "github.com/qmish/2FA/internal/admin/service"
    "github.com/qmish/2FA/internal/api/middlewares"
    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/models"
)

type AdminHandler struct {
    service adminsvc.AdminService
    authz   Authorizer
}

type Authorizer interface {
    HasPermission(ctx context.Context, userID string, role models.UserRole, perm models.Permission) bool
}

func NewAdminHandler(svc adminsvc.AdminService, authz Authorizer) *AdminHandler {
    return &AdminHandler{service: svc, authz: authz}
}

func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminUsersRead) {
        return
    }
    req := dto.AdminUserListRequest{
        Page: parsePage(r),
        Filter: dto.AdminUserFilter{
            Query:  r.URL.Query().Get("query"),
            Status: models.UserStatus(r.URL.Query().Get("status")),
            GroupID: r.URL.Query().Get("group_id"),
        },
    }
    resp, err := h.service.ListUsers(r.Context(), req)
    if err != nil {
        writeError(w, http.StatusBadRequest, "list_users_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminUsersWrite) {
        return
    }
    var req dto.AdminUserCreateRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    resp, err := h.service.CreateUser(r.Context(), req)
    if err != nil {
        writeError(w, http.StatusBadRequest, "create_user_failed")
        return
    }
    writeJSON(w, http.StatusCreated, resp)
}

func (h *AdminHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminUsersWrite) {
        return
    }
    id := r.URL.Query().Get("id")
    if id == "" {
        writeError(w, http.StatusBadRequest, "missing_id")
        return
    }
    var req dto.AdminUserUpdateRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    resp, err := h.service.UpdateUser(r.Context(), id, req)
    if err != nil {
        writeError(w, http.StatusBadRequest, "update_user_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminUsersWrite) {
        return
    }
    id := r.URL.Query().Get("id")
    if id == "" {
        writeError(w, http.StatusBadRequest, "missing_id")
        return
    }
    if err := h.service.DeleteUser(r.Context(), id); err != nil {
        writeError(w, http.StatusBadRequest, "delete_user_failed")
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminPoliciesRead) {
        return
    }
    items, page, err := h.service.ListPolicies(r.Context(), parsePage(r))
    if err != nil {
        writeError(w, http.StatusBadRequest, "list_policies_failed")
        return
    }
    writeJSON(w, http.StatusOK, dto.AdminPolicyListResponse{
        Items: items,
        Page:  page,
    })
}

func (h *AdminHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminPoliciesWrite) {
        return
    }
    var req dto.AdminPolicyCreateRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    resp, err := h.service.CreatePolicy(r.Context(), req)
    if err != nil {
        writeError(w, http.StatusBadRequest, "create_policy_failed")
        return
    }
    writeJSON(w, http.StatusCreated, resp)
}

func (h *AdminHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminPoliciesWrite) {
        return
    }
    id := r.URL.Query().Get("id")
    if id == "" {
        writeError(w, http.StatusBadRequest, "missing_id")
        return
    }
    var req dto.AdminPolicyUpdateRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    resp, err := h.service.UpdatePolicy(r.Context(), id, req)
    if err != nil {
        writeError(w, http.StatusBadRequest, "update_policy_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminPoliciesWrite) {
        return
    }
    id := r.URL.Query().Get("id")
    if id == "" {
        writeError(w, http.StatusBadRequest, "missing_id")
        return
    }
    if err := h.service.DeletePolicy(r.Context(), id); err != nil {
        writeError(w, http.StatusBadRequest, "delete_policy_failed")
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) ListRadiusClients(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminRadiusClientsRead) {
        return
    }
    items, page, err := h.service.ListRadiusClients(r.Context(), parsePage(r))
    if err != nil {
        writeError(w, http.StatusBadRequest, "list_radius_clients_failed")
        return
    }
    writeJSON(w, http.StatusOK, dto.AdminRadiusClientListResponse{
        Items: items,
        Page:  page,
    })
}

func (h *AdminHandler) CreateRadiusClient(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminRadiusClientsWrite) {
        return
    }
    var req dto.AdminRadiusClientCreateRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    resp, err := h.service.CreateRadiusClient(r.Context(), req)
    if err != nil {
        writeError(w, http.StatusBadRequest, "create_radius_client_failed")
        return
    }
    writeJSON(w, http.StatusCreated, resp)
}

func (h *AdminHandler) UpdateRadiusClient(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminRadiusClientsWrite) {
        return
    }
    id := r.URL.Query().Get("id")
    if id == "" {
        writeError(w, http.StatusBadRequest, "missing_id")
        return
    }
    var req dto.AdminRadiusClientUpdateRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    resp, err := h.service.UpdateRadiusClient(r.Context(), id, req)
    if err != nil {
        writeError(w, http.StatusBadRequest, "update_radius_client_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) DeleteRadiusClient(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminRadiusClientsWrite) {
        return
    }
    id := r.URL.Query().Get("id")
    if id == "" {
        writeError(w, http.StatusBadRequest, "missing_id")
        return
    }
    if err := h.service.DeleteRadiusClient(r.Context(), id); err != nil {
        writeError(w, http.StatusBadRequest, "delete_radius_client_failed")
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) ListAuditEvents(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminAuditRead) {
        return
    }
    req := dto.AdminAuditListRequest{
        Page: parsePage(r),
        Filter: dto.AdminAuditFilter{
            ActorUserID: r.URL.Query().Get("actor_user_id"),
            EntityType:  models.AuditEntityType(r.URL.Query().Get("entity_type")),
            Action:      models.AuditAction(r.URL.Query().Get("action")),
            From:        parseTime(r.URL.Query().Get("from")),
            To:          parseTime(r.URL.Query().Get("to")),
        },
    }
    resp, err := h.service.ListAuditEvents(r.Context(), req)
    if err != nil {
        writeError(w, http.StatusBadRequest, "list_audit_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) ListLoginHistory(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminLoginsRead) {
        return
    }
    req := dto.AdminLoginHistoryListRequest{
        Page: parsePage(r),
        Filter: dto.AdminLoginHistoryFilter{
            UserID:  r.URL.Query().Get("user_id"),
            Channel: models.AuthChannel(r.URL.Query().Get("channel")),
            Result:  models.AuthResult(r.URL.Query().Get("result")),
            From:    parseTime(r.URL.Query().Get("from")),
            To:      parseTime(r.URL.Query().Get("to")),
        },
    }
    resp, err := h.service.ListLoginHistory(r.Context(), req)
    if err != nil {
        writeError(w, http.StatusBadRequest, "list_logins_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) ListRadiusRequests(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminRadiusRequestsRead) {
        return
    }
    req := dto.AdminRadiusRequestListRequest{
        Page: parsePage(r),
        Filter: dto.AdminRadiusRequestFilter{
            ClientID: r.URL.Query().Get("client_id"),
            Username: r.URL.Query().Get("username"),
            Result:   models.RadiusResult(r.URL.Query().Get("result")),
            From:     parseTime(r.URL.Query().Get("from")),
            To:       parseTime(r.URL.Query().Get("to")),
        },
    }
    resp, err := h.service.ListRadiusRequests(r.Context(), req)
    if err != nil {
        writeError(w, http.StatusBadRequest, "list_radius_requests_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) GetRolePermissions(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminRolePermissionsRead) {
        return
    }
    role := r.URL.Query().Get("role")
    if role == "" {
        writeError(w, http.StatusBadRequest, "missing_role")
        return
    }
    resp, err := h.service.GetRolePermissions(r.Context(), role)
    if err != nil {
        writeError(w, http.StatusBadRequest, "get_role_permissions_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) SetRolePermissions(w http.ResponseWriter, r *http.Request) {
    if !h.requirePermission(w, r, models.PermissionAdminRolePermissionsWrite) {
        return
    }
    role := r.URL.Query().Get("role")
    if role == "" {
        writeError(w, http.StatusBadRequest, "missing_role")
        return
    }
    var req dto.RolePermissionsUpdateRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_json")
        return
    }
    resp, err := h.service.SetRolePermissions(r.Context(), role, req)
    if err != nil {
        writeError(w, http.StatusBadRequest, "set_role_permissions_failed")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) requirePermission(w http.ResponseWriter, r *http.Request, perm models.Permission) bool {
    claims, ok := middlewares.AdminClaimsFromContext(r.Context())
    if !ok {
        w.WriteHeader(http.StatusUnauthorized)
        return false
    }
    if h.authz == nil {
        return true
    }
    if !h.authz.HasPermission(r.Context(), claims.UserID, models.UserRole(claims.Role), perm) {
        w.WriteHeader(http.StatusForbidden)
        return false
    }
    return true
}

func parsePage(r *http.Request) dto.PageRequest {
    return dto.PageRequest{
        Limit:     parseInt(r.URL.Query().Get("limit"), 50),
        Offset:    parseInt(r.URL.Query().Get("offset"), 0),
        SortBy:    r.URL.Query().Get("sort_by"),
        SortOrder: r.URL.Query().Get("sort_order"),
    }
}

func parseInt(val string, fallback int) int {
    if val == "" {
        return fallback
    }
    i, err := strconv.Atoi(val)
    if err != nil {
        return fallback
    }
    return i
}

func parseTime(val string) time.Time {
    if val == "" {
        return time.Time{}
    }
    t, err := time.Parse(time.RFC3339, val)
    if err != nil {
        return time.Time{}
    }
    return t
}
