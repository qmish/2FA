package handlers

import (
    "context"
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
