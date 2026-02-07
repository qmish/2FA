package handlers

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	adminsvc "github.com/qmish/2FA/internal/admin/service"
	"github.com/qmish/2FA/internal/api/middlewares"
	"github.com/qmish/2FA/internal/dto"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/pkg/validator"
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
			Query:   r.URL.Query().Get("query"),
			Status:  models.UserStatus(r.URL.Query().Get("status")),
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

func (h *AdminHandler) ExportUsers(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminUsersRead) {
		return
	}
	req := dto.AdminUserListRequest{
		Page: parsePage(r),
		Filter: dto.AdminUserFilter{
			Query:   r.URL.Query().Get("query"),
			Status:  models.UserStatus(r.URL.Query().Get("status")),
			GroupID: r.URL.Query().Get("group_id"),
		},
	}
	resp, err := h.service.ListUsers(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "export_users_failed")
		return
	}
	if strings.EqualFold(r.URL.Query().Get("format"), "csv") {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=users.csv")
		w.WriteHeader(http.StatusOK)
		writer := csv.NewWriter(w)
		_ = writer.Write([]string{"id", "username", "email", "phone", "status", "role"})
		for _, item := range resp.Items {
			_ = writer.Write([]string{
				item.ID,
				item.Username,
				item.Email,
				item.Phone,
				string(item.Status),
				string(item.Role),
			})
		}
		writer.Flush()
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
	req.Username = strings.TrimSpace(req.Username)
	req.Email = validator.NormalizeEmail(req.Email)
	req.Phone = validator.NormalizePhone(req.Phone)
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_input")
		return
	}
	if req.Email != "" && !validator.IsEmailValid(req.Email) {
		writeError(w, http.StatusBadRequest, "invalid_email")
		return
	}
	if req.Phone != "" && !validator.IsPhoneValid(req.Phone) {
		writeError(w, http.StatusBadRequest, "invalid_phone")
		return
	}
	resp, err := h.service.CreateUser(r.Context(), req)
	if err != nil {
		if errors.Is(err, adminsvc.ErrConflict) {
			writeError(w, http.StatusConflict, "user_conflict")
			return
		}
		writeError(w, http.StatusBadRequest, "create_user_failed")
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *AdminHandler) ImportUsers(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminUsersWrite) {
		return
	}
	items, err := parseCSVUsers(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_csv")
		return
	}
	resp, err := h.service.BulkCreateUsers(r.Context(), dto.AdminUserBulkRequest{Items: items})
	if err != nil {
		writeError(w, http.StatusBadRequest, "import_users_failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) CreateInvite(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminUsersWrite) {
		return
	}
	var req dto.AdminInviteCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	resp, err := h.service.CreateInvite(r.Context(), req)
	if err != nil {
		if errors.Is(err, adminsvc.ErrInvalidInput) {
			writeError(w, http.StatusBadRequest, "invalid_input")
			return
		}
		if errors.Is(err, adminsvc.ErrNotImplemented) {
			writeError(w, http.StatusNotImplemented, "not_implemented")
			return
		}
		writeError(w, http.StatusBadRequest, "create_invite_failed")
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func parseCSVUsers(body io.Reader) ([]dto.AdminUserCreateRequest, error) {
	reader := csv.NewReader(body)
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("empty csv")
	}
	header := map[string]int{}
	start := 0
	if isHeaderRow(records[0]) {
		for idx, col := range records[0] {
			key := strings.ToLower(strings.TrimSpace(col))
			if key != "" {
				header[key] = idx
			}
		}
		start = 1
	}
	items := make([]dto.AdminUserCreateRequest, 0, len(records))
	for i := start; i < len(records); i++ {
		row := records[i]
		if len(row) == 0 || (len(row) == 1 && strings.TrimSpace(row[0]) == "") {
			continue
		}
		get := func(name string, idx int) string {
			if len(header) > 0 {
				if pos, ok := header[name]; ok && pos < len(row) {
					return strings.TrimSpace(row[pos])
				}
				return ""
			}
			if idx < len(row) {
				return strings.TrimSpace(row[idx])
			}
			return ""
		}
		items = append(items, dto.AdminUserCreateRequest{
			Username: get("username", 0),
			Email:    get("email", 1),
			Phone:    get("phone", 2),
			Status:   models.UserStatus(get("status", 3)),
			Role:     models.UserRole(get("role", 4)),
			Password: get("password", 5),
		})
	}
	return items, nil
}

func isHeaderRow(row []string) bool {
	for _, col := range row {
		switch strings.ToLower(strings.TrimSpace(col)) {
		case "username", "email", "phone", "status", "role", "password":
			return true
		}
	}
	return false
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
	req.Email = validator.NormalizeEmail(req.Email)
	req.Phone = validator.NormalizePhone(req.Phone)
	if req.Email != "" && !validator.IsEmailValid(req.Email) {
		writeError(w, http.StatusBadRequest, "invalid_email")
		return
	}
	if req.Phone != "" && !validator.IsPhoneValid(req.Phone) {
		writeError(w, http.StatusBadRequest, "invalid_phone")
		return
	}
	resp, err := h.service.UpdateUser(r.Context(), id, req)
	if err != nil {
		if errors.Is(err, adminsvc.ErrConflict) {
			writeError(w, http.StatusConflict, "user_conflict")
			return
		}
		if errors.Is(err, adminsvc.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user_not_found")
			return
		}
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
		if errors.Is(err, adminsvc.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user_not_found")
			return
		}
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
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_input")
		return
	}
	resp, err := h.service.CreatePolicy(r.Context(), req)
	if err != nil {
		if errors.Is(err, adminsvc.ErrConflict) {
			writeError(w, http.StatusConflict, "policy_conflict")
			return
		}
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
	req.Name = strings.TrimSpace(req.Name)
	resp, err := h.service.UpdatePolicy(r.Context(), id, req)
	if err != nil {
		if errors.Is(err, adminsvc.ErrConflict) {
			writeError(w, http.StatusConflict, "policy_conflict")
			return
		}
		if errors.Is(err, adminsvc.ErrNotFound) {
			writeError(w, http.StatusNotFound, "policy_not_found")
			return
		}
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
		if errors.Is(err, adminsvc.ErrNotFound) {
			writeError(w, http.StatusNotFound, "policy_not_found")
			return
		}
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
	req.Name = strings.TrimSpace(req.Name)
	req.IP = validator.NormalizeIP(req.IP)
	if req.Name == "" || req.IP == "" || req.Secret == "" {
		writeError(w, http.StatusBadRequest, "invalid_input")
		return
	}
	if !validator.IsIPValid(req.IP) {
		writeError(w, http.StatusBadRequest, "invalid_ip")
		return
	}
	resp, err := h.service.CreateRadiusClient(r.Context(), req)
	if err != nil {
		if errors.Is(err, adminsvc.ErrConflict) {
			writeError(w, http.StatusConflict, "radius_client_conflict")
			return
		}
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
	req.Name = strings.TrimSpace(req.Name)
	resp, err := h.service.UpdateRadiusClient(r.Context(), id, req)
	if err != nil {
		if errors.Is(err, adminsvc.ErrNotFound) {
			writeError(w, http.StatusNotFound, "radius_client_not_found")
			return
		}
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
		if errors.Is(err, adminsvc.ErrNotFound) {
			writeError(w, http.StatusNotFound, "radius_client_not_found")
			return
		}
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
			EntityID:    r.URL.Query().Get("entity_id"),
			IP:          r.URL.Query().Get("ip"),
			Payload:     r.URL.Query().Get("payload"),
			Query:       r.URL.Query().Get("query"),
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

func (h *AdminHandler) ExportAuditEvents(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminAuditRead) {
		return
	}
	req := dto.AdminAuditListRequest{
		Page: parsePage(r),
		Filter: dto.AdminAuditFilter{
			ActorUserID: r.URL.Query().Get("actor_user_id"),
			EntityType:  models.AuditEntityType(r.URL.Query().Get("entity_type")),
			Action:      models.AuditAction(r.URL.Query().Get("action")),
			EntityID:    r.URL.Query().Get("entity_id"),
			IP:          r.URL.Query().Get("ip"),
			Payload:     r.URL.Query().Get("payload"),
			Query:       r.URL.Query().Get("query"),
			From:        parseTime(r.URL.Query().Get("from")),
			To:          parseTime(r.URL.Query().Get("to")),
		},
	}
	resp, err := h.service.ListAuditEvents(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "export_audit_failed")
		return
	}
	if strings.EqualFold(r.URL.Query().Get("format"), "csv") {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=audit.csv")
		w.WriteHeader(http.StatusOK)
		writer := csv.NewWriter(w)
		_ = writer.Write([]string{"id", "actor_user_id", "action", "entity_type", "entity_id", "payload", "ip", "created_at"})
		for _, item := range resp.Items {
			_ = writer.Write([]string{
				item.ID,
				item.ActorUserID,
				string(item.Action),
				string(item.EntityType),
				item.EntityID,
				item.Payload,
				item.IP,
				item.CreatedAt.Format(time.RFC3339),
			})
		}
		writer.Flush()
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
			UserID:   r.URL.Query().Get("user_id"),
			Channel:  models.AuthChannel(r.URL.Query().Get("channel")),
			Result:   models.AuthResult(r.URL.Query().Get("result")),
			IP:       r.URL.Query().Get("ip"),
			DeviceID: r.URL.Query().Get("device_id"),
			From:     parseTime(r.URL.Query().Get("from")),
			To:       parseTime(r.URL.Query().Get("to")),
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

func (h *AdminHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminUsersRead) {
		return
	}
	req := dto.AdminSessionListRequest{
		Page: parsePage(r),
		Filter: dto.AdminSessionFilter{
			UserID:     r.URL.Query().Get("user_id"),
			ActiveOnly: parseBool(r.URL.Query().Get("active_only")),
			IP:         r.URL.Query().Get("ip"),
			UserAgent:  r.URL.Query().Get("user_agent"),
		},
	}
	resp, err := h.service.ListSessions(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "list_sessions_failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminUsersWrite) {
		return
	}
	claims, ok := middlewares.AdminClaimsFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req dto.AdminSessionRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "invalid_input")
		return
	}
	if err := h.service.RevokeSession(r.Context(), claims.UserID, req.SessionID, clientIP(r)); err != nil {
		writeError(w, http.StatusBadRequest, "revoke_session_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) RevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminUsersWrite) {
		return
	}
	claims, ok := middlewares.AdminClaimsFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req dto.AdminUserSessionsRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, "invalid_input")
		return
	}
	if err := h.service.RevokeUserSessions(r.Context(), claims.UserID, req.UserID, req.ExceptSessionID, clientIP(r)); err != nil {
		writeError(w, http.StatusBadRequest, "revoke_sessions_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) ListLockouts(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminUsersRead) {
		return
	}
	req := dto.AdminLockoutListRequest{
		Page: parsePage(r),
		Filter: dto.AdminLockoutFilter{
			UserID:     r.URL.Query().Get("user_id"),
			IP:         r.URL.Query().Get("ip"),
			Reason:     r.URL.Query().Get("reason"),
			ActiveOnly: parseBool(r.URL.Query().Get("active_only")),
		},
	}
	resp, err := h.service.ListLockouts(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "list_lockouts_failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) ClearLockouts(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminUsersWrite) {
		return
	}
	claims, ok := middlewares.AdminClaimsFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req dto.AdminLockoutClearRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if req.UserID == "" && req.IP == "" && req.Reason == "" {
		writeError(w, http.StatusBadRequest, "invalid_input")
		return
	}
	if err := h.service.ClearLockouts(r.Context(), claims.UserID, req); err != nil {
		writeError(w, http.StatusBadRequest, "clear_lockouts_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
		if errors.Is(err, adminsvc.ErrRolePermissionsStoreMissing) {
			writeError(w, http.StatusBadRequest, "role_permissions_unavailable")
			return
		}
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
		if errors.Is(err, adminsvc.ErrRolePermissionsStoreMissing) {
			writeError(w, http.StatusBadRequest, "role_permissions_unavailable")
			return
		}
		writeError(w, http.StatusBadRequest, "set_role_permissions_failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminGroupsRead) {
		return
	}
	resp, err := h.service.ListGroups(r.Context(), parsePage(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, "list_groups_failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminGroupsWrite) {
		return
	}
	var req dto.AdminGroupCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_input")
		return
	}
	resp, err := h.service.CreateGroup(r.Context(), req)
	if err != nil {
		if errors.Is(err, adminsvc.ErrConflict) {
			writeError(w, http.StatusConflict, "group_conflict")
			return
		}
		writeError(w, http.StatusBadRequest, "create_group_failed")
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *AdminHandler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminGroupsWrite) {
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing_id")
		return
	}
	var req dto.AdminGroupUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	resp, err := h.service.UpdateGroup(r.Context(), id, req)
	if err != nil {
		if errors.Is(err, adminsvc.ErrConflict) {
			writeError(w, http.StatusConflict, "group_conflict")
			return
		}
		if errors.Is(err, adminsvc.ErrNotFound) {
			writeError(w, http.StatusNotFound, "group_not_found")
			return
		}
		writeError(w, http.StatusBadRequest, "update_group_failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminGroupsWrite) {
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing_id")
		return
	}
	if err := h.service.DeleteGroup(r.Context(), id); err != nil {
		if errors.Is(err, adminsvc.ErrNotFound) {
			writeError(w, http.StatusNotFound, "group_not_found")
			return
		}
		writeError(w, http.StatusBadRequest, "delete_group_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminGroupsWrite) {
		return
	}
	groupID := r.URL.Query().Get("group_id")
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "missing_group_id")
		return
	}
	var req dto.AdminGroupMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, "missing_user_id")
		return
	}
	if err := h.service.AddGroupMember(r.Context(), groupID, req); err != nil {
		writeError(w, http.StatusBadRequest, "add_group_member_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) RemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminGroupsWrite) {
		return
	}
	groupID := r.URL.Query().Get("group_id")
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "missing_group_id")
		return
	}
	var req dto.AdminGroupMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, "missing_user_id")
		return
	}
	if err := h.service.RemoveGroupMember(r.Context(), groupID, req); err != nil {
		writeError(w, http.StatusBadRequest, "remove_group_member_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) ListGroupMembers(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminGroupsRead) {
		return
	}
	groupID := r.URL.Query().Get("group_id")
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "missing_group_id")
		return
	}
	resp, err := h.service.ListGroupMembers(r.Context(), groupID, parsePage(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, "list_group_members_failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) SetGroupPolicy(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminGroupsWrite) {
		return
	}
	groupID := r.URL.Query().Get("group_id")
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "missing_group_id")
		return
	}
	var req dto.AdminGroupPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if req.PolicyID == "" {
		writeError(w, http.StatusBadRequest, "missing_policy_id")
		return
	}
	if err := h.service.SetGroupPolicy(r.Context(), groupID, req); err != nil {
		writeError(w, http.StatusBadRequest, "set_group_policy_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) ClearGroupPolicy(w http.ResponseWriter, r *http.Request) {
	if !h.requirePermission(w, r, models.PermissionAdminGroupsWrite) {
		return
	}
	groupID := r.URL.Query().Get("group_id")
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "missing_group_id")
		return
	}
	if err := h.service.ClearGroupPolicy(r.Context(), groupID); err != nil {
		writeError(w, http.StatusBadRequest, "clear_group_policy_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

func parseBool(val string) bool {
	if val == "" {
		return false
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return false
	}
	return b
}
