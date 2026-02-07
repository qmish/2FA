package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	adminsvc "github.com/qmish/2FA/internal/admin/service"
	"github.com/qmish/2FA/internal/api/middlewares"
	"github.com/qmish/2FA/internal/dto"
	"github.com/qmish/2FA/internal/models"
)

func TestAdminListUsers(t *testing.T) {
	authz := fakeAuthorizer{}
	svc := &adminsvc.MockAdminService{
		ListUsersFunc: func(ctx context.Context, req dto.AdminUserListRequest) (dto.AdminUserListResponse, error) {
			if req.Page.Limit != 10 || req.Filter.Status != models.UserActive {
				t.Fatalf("unexpected request: %+v", req)
			}
			return dto.AdminUserListResponse{
				Items: []dto.AdminUserListItem{{ID: "u1", Username: "alice", Status: models.UserActive}},
				Page:  dto.PageResponse{Total: 1, Limit: 10, Offset: 0},
			}, nil
		},
		ListPoliciesFunc: func(ctx context.Context, req dto.PageRequest) ([]dto.AdminPolicyDTO, dto.PageResponse, error) {
			return nil, dto.PageResponse{}, nil
		},
		ListRadiusClientsFunc: func(ctx context.Context, req dto.PageRequest) ([]dto.AdminRadiusClientDTO, dto.PageResponse, error) {
			return nil, dto.PageResponse{}, nil
		},
		ListAuditEventsFunc: func(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error) {
			return dto.AdminAuditListResponse{}, nil
		},
		ListLoginHistoryFunc: func(ctx context.Context, req dto.AdminLoginHistoryListRequest) (dto.AdminLoginHistoryListResponse, error) {
			return dto.AdminLoginHistoryListResponse{}, nil
		},
		ListRadiusRequestsFunc: func(ctx context.Context, req dto.AdminRadiusRequestListRequest) (dto.AdminRadiusRequestListResponse, error) {
			return dto.AdminRadiusRequestListResponse{}, nil
		},
	}

	handler := NewAdminHandler(svc, authz)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users?limit=10&status=active", nil)
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.ListUsers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAdminCreateUser(t *testing.T) {
	authz := fakeAuthorizer{}
	svc := &adminsvc.MockAdminService{
		CreateUserFunc: func(ctx context.Context, req dto.AdminUserCreateRequest) (dto.AdminUserResponse, error) {
			return dto.AdminUserResponse{ID: "u1", Username: req.Username, Role: req.Role}, nil
		},
		ListUsersFunc: func(ctx context.Context, req dto.AdminUserListRequest) (dto.AdminUserListResponse, error) {
			return dto.AdminUserListResponse{}, nil
		},
		ListPoliciesFunc: func(ctx context.Context, req dto.PageRequest) ([]dto.AdminPolicyDTO, dto.PageResponse, error) {
			return nil, dto.PageResponse{}, nil
		},
		ListRadiusClientsFunc: func(ctx context.Context, req dto.PageRequest) ([]dto.AdminRadiusClientDTO, dto.PageResponse, error) {
			return nil, dto.PageResponse{}, nil
		},
		ListAuditEventsFunc: func(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error) {
			return dto.AdminAuditListResponse{}, nil
		},
		ListLoginHistoryFunc: func(ctx context.Context, req dto.AdminLoginHistoryListRequest) (dto.AdminLoginHistoryListResponse, error) {
			return dto.AdminLoginHistoryListResponse{}, nil
		},
		ListRadiusRequestsFunc: func(ctx context.Context, req dto.AdminRadiusRequestListRequest) (dto.AdminRadiusRequestListResponse, error) {
			return dto.AdminRadiusRequestListResponse{}, nil
		},
		UpdateUserFunc: func(ctx context.Context, id string, req dto.AdminUserUpdateRequest) (dto.AdminUserResponse, error) {
			return dto.AdminUserResponse{}, nil
		},
		DeleteUserFunc: func(ctx context.Context, id string) error { return nil },
		CreatePolicyFunc: func(ctx context.Context, req dto.AdminPolicyCreateRequest) (dto.AdminPolicyDTO, error) {
			return dto.AdminPolicyDTO{}, nil
		},
		UpdatePolicyFunc: func(ctx context.Context, id string, req dto.AdminPolicyUpdateRequest) (dto.AdminPolicyDTO, error) {
			return dto.AdminPolicyDTO{}, nil
		},
		DeletePolicyFunc: func(ctx context.Context, id string) error { return nil },
		CreateRadiusClientFunc: func(ctx context.Context, req dto.AdminRadiusClientCreateRequest) (dto.AdminRadiusClientDTO, error) {
			return dto.AdminRadiusClientDTO{}, nil
		},
		UpdateRadiusClientFunc: func(ctx context.Context, id string, req dto.AdminRadiusClientUpdateRequest) (dto.AdminRadiusClientDTO, error) {
			return dto.AdminRadiusClientDTO{}, nil
		},
		DeleteRadiusClientFunc: func(ctx context.Context, id string) error { return nil },
		GetRolePermissionsFunc: func(ctx context.Context, role string) (dto.RolePermissionsResponse, error) {
			return dto.RolePermissionsResponse{}, nil
		},
		SetRolePermissionsFunc: func(ctx context.Context, role string, req dto.RolePermissionsUpdateRequest) (dto.RolePermissionsResponse, error) {
			return dto.RolePermissionsResponse{}, nil
		},
	}

	handler := NewAdminHandler(svc, authz)
	body := bytes.NewBufferString(`{"username":"bob","password":"secret","status":"active","role":"user"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/create", body)
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.CreateUser(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAdminExportUsersCSV(t *testing.T) {
	authz := fakeAuthorizer{}
	svc := &adminsvc.MockAdminService{
		ListUsersFunc: func(ctx context.Context, req dto.AdminUserListRequest) (dto.AdminUserListResponse, error) {
			return dto.AdminUserListResponse{
				Items: []dto.AdminUserListItem{
					{ID: "u1", Username: "alice", Email: "a@example.com", Status: models.UserActive, Role: models.RoleUser},
				},
				Page: dto.PageResponse{Total: 1, Limit: 10, Offset: 0},
			}, nil
		},
	}

	handler := NewAdminHandler(svc, authz)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/export?format=csv", nil)
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.ExportUsers(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/csv" {
		t.Fatalf("unexpected content type: %s", ct)
	}
	if !strings.Contains(rec.Body.String(), "alice") {
		t.Fatalf("expected user in csv, got %s", rec.Body.String())
	}
}

func TestAdminImportUsers(t *testing.T) {
	authz := fakeAuthorizer{}
	svc := &adminsvc.MockAdminService{
		BulkCreateUsersFunc: func(ctx context.Context, req dto.AdminUserBulkRequest) (dto.AdminUserBulkResponse, error) {
			if len(req.Items) != 2 {
				t.Fatalf("unexpected items: %+v", req.Items)
			}
			return dto.AdminUserBulkResponse{Created: 2, Failed: 0}, nil
		},
	}

	handler := NewAdminHandler(svc, authz)
	body := bytes.NewBufferString("username,email,phone,status,role,password\nalice,a@example.com,,active,user,pass\nbob,b@example.com,,active,user,pass\n")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/import", body)
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.ImportUsers(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAdminCreateInvite(t *testing.T) {
	authz := fakeAuthorizer{}
	svc := &adminsvc.MockAdminService{
		CreateInviteFunc: func(ctx context.Context, req dto.AdminInviteCreateRequest) (dto.AdminInviteResponse, error) {
			return dto.AdminInviteResponse{ID: "i1", Token: "token", Email: req.Email, Role: req.Role, ExpiresAt: time.Now().Unix()}, nil
		},
		ListUsersFunc: func(ctx context.Context, req dto.AdminUserListRequest) (dto.AdminUserListResponse, error) {
			return dto.AdminUserListResponse{}, nil
		},
		ListPoliciesFunc: func(ctx context.Context, req dto.PageRequest) ([]dto.AdminPolicyDTO, dto.PageResponse, error) {
			return nil, dto.PageResponse{}, nil
		},
		ListRadiusClientsFunc: func(ctx context.Context, req dto.PageRequest) ([]dto.AdminRadiusClientDTO, dto.PageResponse, error) {
			return nil, dto.PageResponse{}, nil
		},
		ListAuditEventsFunc: func(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error) {
			return dto.AdminAuditListResponse{}, nil
		},
		ListLoginHistoryFunc: func(ctx context.Context, req dto.AdminLoginHistoryListRequest) (dto.AdminLoginHistoryListResponse, error) {
			return dto.AdminLoginHistoryListResponse{}, nil
		},
		ListRadiusRequestsFunc: func(ctx context.Context, req dto.AdminRadiusRequestListRequest) (dto.AdminRadiusRequestListResponse, error) {
			return dto.AdminRadiusRequestListResponse{}, nil
		},
	}

	handler := NewAdminHandler(svc, authz)
	body := bytes.NewBufferString(`{"email":"alice@example.com","role":"user","ttl_minutes":60}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/invites/create", body)
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.CreateInvite(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAdminCreateGroup(t *testing.T) {
	authz := fakeAuthorizer{}
	svc := &adminsvc.MockAdminService{
		CreateGroupFunc: func(ctx context.Context, req dto.AdminGroupCreateRequest) (dto.AdminGroupResponse, error) {
			return dto.AdminGroupResponse{ID: "g1", Name: req.Name}, nil
		},
		ListUsersFunc: func(ctx context.Context, req dto.AdminUserListRequest) (dto.AdminUserListResponse, error) {
			return dto.AdminUserListResponse{}, nil
		},
		CreateUserFunc: func(ctx context.Context, req dto.AdminUserCreateRequest) (dto.AdminUserResponse, error) {
			return dto.AdminUserResponse{}, nil
		},
		UpdateUserFunc: func(ctx context.Context, id string, req dto.AdminUserUpdateRequest) (dto.AdminUserResponse, error) {
			return dto.AdminUserResponse{}, nil
		},
		DeleteUserFunc: func(ctx context.Context, id string) error { return nil },
		ListPoliciesFunc: func(ctx context.Context, req dto.PageRequest) ([]dto.AdminPolicyDTO, dto.PageResponse, error) {
			return nil, dto.PageResponse{}, nil
		},
		CreatePolicyFunc: func(ctx context.Context, req dto.AdminPolicyCreateRequest) (dto.AdminPolicyDTO, error) {
			return dto.AdminPolicyDTO{}, nil
		},
		UpdatePolicyFunc: func(ctx context.Context, id string, req dto.AdminPolicyUpdateRequest) (dto.AdminPolicyDTO, error) {
			return dto.AdminPolicyDTO{}, nil
		},
		DeletePolicyFunc: func(ctx context.Context, id string) error { return nil },
		ListRadiusClientsFunc: func(ctx context.Context, req dto.PageRequest) ([]dto.AdminRadiusClientDTO, dto.PageResponse, error) {
			return nil, dto.PageResponse{}, nil
		},
		CreateRadiusClientFunc: func(ctx context.Context, req dto.AdminRadiusClientCreateRequest) (dto.AdminRadiusClientDTO, error) {
			return dto.AdminRadiusClientDTO{}, nil
		},
		UpdateRadiusClientFunc: func(ctx context.Context, id string, req dto.AdminRadiusClientUpdateRequest) (dto.AdminRadiusClientDTO, error) {
			return dto.AdminRadiusClientDTO{}, nil
		},
		DeleteRadiusClientFunc: func(ctx context.Context, id string) error { return nil },
		GetRolePermissionsFunc: func(ctx context.Context, role string) (dto.RolePermissionsResponse, error) {
			return dto.RolePermissionsResponse{}, nil
		},
		SetRolePermissionsFunc: func(ctx context.Context, role string, req dto.RolePermissionsUpdateRequest) (dto.RolePermissionsResponse, error) {
			return dto.RolePermissionsResponse{}, nil
		},
		ListAuditEventsFunc: func(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error) {
			return dto.AdminAuditListResponse{}, nil
		},
		ListLoginHistoryFunc: func(ctx context.Context, req dto.AdminLoginHistoryListRequest) (dto.AdminLoginHistoryListResponse, error) {
			return dto.AdminLoginHistoryListResponse{}, nil
		},
		ListRadiusRequestsFunc: func(ctx context.Context, req dto.AdminRadiusRequestListRequest) (dto.AdminRadiusRequestListResponse, error) {
			return dto.AdminRadiusRequestListResponse{}, nil
		},
		AddGroupMemberFunc:    func(ctx context.Context, groupID string, req dto.AdminGroupMemberRequest) error { return nil },
		RemoveGroupMemberFunc: func(ctx context.Context, groupID string, req dto.AdminGroupMemberRequest) error { return nil },
		ListGroupMembersFunc: func(ctx context.Context, groupID string, page dto.PageRequest) (dto.AdminGroupMembersResponse, error) {
			return dto.AdminGroupMembersResponse{}, nil
		},
		SetGroupPolicyFunc:   func(ctx context.Context, groupID string, req dto.AdminGroupPolicyRequest) error { return nil },
		ClearGroupPolicyFunc: func(ctx context.Context, groupID string) error { return nil },
		UpdateGroupFunc: func(ctx context.Context, id string, req dto.AdminGroupUpdateRequest) (dto.AdminGroupResponse, error) {
			return dto.AdminGroupResponse{}, nil
		},
		DeleteGroupFunc: func(ctx context.Context, id string) error { return nil },
		ListGroupsFunc: func(ctx context.Context, req dto.PageRequest) (dto.AdminGroupListResponse, error) {
			return dto.AdminGroupListResponse{}, nil
		},
	}

	handler := NewAdminHandler(svc, authz)
	body := bytes.NewBufferString(`{"name":"ops","description":"ops team"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/groups/create", body)
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.CreateGroup(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAdminListSessions(t *testing.T) {
	authz := fakeAuthorizer{}
	svc := &adminsvc.MockAdminService{
		ListSessionsFunc: func(ctx context.Context, req dto.AdminSessionListRequest) (dto.AdminSessionListResponse, error) {
			if req.Filter.UserID != "u1" || !req.Filter.ActiveOnly || req.Filter.IP != "127.0.0.1" || req.Filter.UserAgent != "ua" {
				t.Fatalf("unexpected filter: %+v", req.Filter)
			}
			return dto.AdminSessionListResponse{}, nil
		},
	}
	handler := NewAdminHandler(svc, authz)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/sessions?user_id=u1&active_only=true&ip=127.0.0.1&user_agent=ua", nil)
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.ListSessions(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAdminListLoginHistory(t *testing.T) {
	authz := fakeAuthorizer{}
	svc := &adminsvc.MockAdminService{
		ListLoginHistoryFunc: func(ctx context.Context, req dto.AdminLoginHistoryListRequest) (dto.AdminLoginHistoryListResponse, error) {
			if req.Filter.UserID != "u1" || req.Filter.Channel != models.AuthChannel("web") || req.Filter.Result != models.AuthResult("deny") {
				t.Fatalf("unexpected filter: %+v", req.Filter)
			}
			if req.Filter.IP != "127.0.0.1" || req.Filter.DeviceID != "device-1" {
				t.Fatalf("unexpected filter extra: %+v", req.Filter)
			}
			if req.Page.Limit != 10 || req.Page.Offset != 5 {
				t.Fatalf("unexpected page: %+v", req.Page)
			}
			return dto.AdminLoginHistoryListResponse{}, nil
		},
	}
	handler := NewAdminHandler(svc, authz)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/logins?user_id=u1&channel=web&result=deny&ip=127.0.0.1&device_id=device-1&limit=10&offset=5", nil)
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.ListLoginHistory(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAdminRevokeSessionInvalidInput(t *testing.T) {
	authz := fakeAuthorizer{}
	svc := &adminsvc.MockAdminService{
		RevokeSessionFunc: func(ctx context.Context, actorUserID string, sessionID string, ip string) error { return nil },
	}
	handler := NewAdminHandler(svc, authz)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/sessions/revoke", bytes.NewBufferString(`{}`))
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.RevokeSession(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAdminRevokeSessionOK(t *testing.T) {
	authz := fakeAuthorizer{}
	svc := &adminsvc.MockAdminService{
		RevokeSessionFunc: func(ctx context.Context, actorUserID string, sessionID string, ip string) error {
			if actorUserID != "admin1" || sessionID != "s1" || ip == "" {
				t.Fatalf("unexpected args: actor=%s session=%s ip=%s", actorUserID, sessionID, ip)
			}
			return nil
		},
	}
	handler := NewAdminHandler(svc, authz)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/sessions/revoke", bytes.NewBufferString(`{"session_id":"s1"}`))
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "admin1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.RevokeSession(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAdminRevokeUserSessionsOK(t *testing.T) {
	authz := fakeAuthorizer{}
	svc := &adminsvc.MockAdminService{
		RevokeUserSessionsFunc: func(ctx context.Context, actorUserID string, userID string, exceptSessionID string, ip string) error {
			if actorUserID != "admin1" || userID != "u2" || exceptSessionID != "s9" || ip == "" {
				t.Fatalf("unexpected args: actor=%s user=%s except=%s ip=%s", actorUserID, userID, exceptSessionID, ip)
			}
			return nil
		},
	}
	handler := NewAdminHandler(svc, authz)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/sessions/revoke_user", bytes.NewBufferString(`{"user_id":"u2","except_session_id":"s9"}`))
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "admin1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.RevokeUserSessions(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAdminListLockouts(t *testing.T) {
	authz := fakeAuthorizer{}
	svc := &adminsvc.MockAdminService{
		ListLockoutsFunc: func(ctx context.Context, req dto.AdminLockoutListRequest) (dto.AdminLockoutListResponse, error) {
			if req.Filter.UserID != "u1" || req.Filter.IP != "127.0.0.1" || req.Filter.Reason != "too_many_attempts" || !req.Filter.ActiveOnly {
				t.Fatalf("unexpected filter: %+v", req.Filter)
			}
			return dto.AdminLockoutListResponse{}, nil
		},
	}
	handler := NewAdminHandler(svc, authz)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/lockouts?user_id=u1&ip=127.0.0.1&reason=too_many_attempts&active_only=true", nil)
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.ListLockouts(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAdminClearLockoutsInvalidInput(t *testing.T) {
	authz := fakeAuthorizer{}
	svc := &adminsvc.MockAdminService{
		ClearLockoutsFunc: func(ctx context.Context, actorUserID string, req dto.AdminLockoutClearRequest) error { return nil },
	}
	handler := NewAdminHandler(svc, authz)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/lockouts/clear", bytes.NewBufferString(`{}`))
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.ClearLockouts(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAdminClearLockoutsOK(t *testing.T) {
	authz := fakeAuthorizer{}
	svc := &adminsvc.MockAdminService{
		ClearLockoutsFunc: func(ctx context.Context, actorUserID string, req dto.AdminLockoutClearRequest) error {
			if actorUserID != "admin1" || req.Reason != "too_many_attempts" {
				t.Fatalf("unexpected args: actor=%s req=%+v", actorUserID, req)
			}
			return nil
		},
	}
	handler := NewAdminHandler(svc, authz)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/lockouts/clear", bytes.NewBufferString(`{"reason":"too_many_attempts"}`))
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "admin1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.ClearLockouts(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAdminExportAuditEvents(t *testing.T) {
	authz := fakeAuthorizer{}
	svc := &adminsvc.MockAdminService{
		ListAuditEventsFunc: func(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error) {
			return dto.AdminAuditListResponse{}, nil
		},
	}
	handler := NewAdminHandler(svc, authz)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit/export", nil)
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.ExportAuditEvents(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAdminExportAuditEventsCSV(t *testing.T) {
	authz := fakeAuthorizer{}
	svc := &adminsvc.MockAdminService{
		ListAuditEventsFunc: func(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error) {
			return dto.AdminAuditListResponse{
				Items: []dto.AdminAuditEventDTO{
					{ID: "a1", ActorUserID: "u1", Action: models.AuditLogin, EntityType: models.AuditEntityUser, EntityID: "u1", Payload: "success"},
				},
			}, nil
		},
	}
	handler := NewAdminHandler(svc, authz)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit/export?format=csv", nil)
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.ExportAuditEvents(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/csv" {
		t.Fatalf("unexpected content type: %s", ct)
	}
	if !strings.Contains(rec.Body.String(), "payload") || !strings.Contains(rec.Body.String(), "success") {
		t.Fatalf("expected payload in csv, got %s", rec.Body.String())
	}
}

func TestAdminListAuditEventsFilters(t *testing.T) {
	authz := fakeAuthorizer{}
	expectedFrom, _ := time.Parse(time.RFC3339, "2026-02-05T15:00:00Z")
	expectedTo, _ := time.Parse(time.RFC3339, "2026-02-06T15:00:00Z")
	svc := &adminsvc.MockAdminService{
		ListAuditEventsFunc: func(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error) {
			if req.Filter.ActorUserID != "u1" || req.Filter.EntityType != models.AuditEntitySession || req.Filter.Action != models.AuditLogout || req.Filter.EntityID != "s1" || req.Filter.IP != "127.0.0.1" || req.Filter.Payload != "payload" || req.Filter.Query != "search" {
				t.Fatalf("unexpected filter: %+v", req.Filter)
			}
			if !req.Filter.From.Equal(expectedFrom) || !req.Filter.To.Equal(expectedTo) {
				t.Fatalf("unexpected time filter: %+v", req.Filter)
			}
			return dto.AdminAuditListResponse{}, nil
		},
	}
	handler := NewAdminHandler(svc, authz)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit/events?actor_user_id=u1&entity_type=session&action=logout&entity_id=s1&ip=127.0.0.1&payload=payload&query=search&from=2026-02-05T15:00:00Z&to=2026-02-06T15:00:00Z", nil)
	req = req.WithContext(middlewares.WithAdminClaims(req.Context(), &middlewares.AdminClaims{UserID: "u1", Role: "admin"}))
	rec := httptest.NewRecorder()

	handler.ListAuditEvents(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

type fakeAuthorizer struct{}

func (fakeAuthorizer) HasPermission(ctx context.Context, userID string, role models.UserRole, perm models.Permission) bool {
	return true
}
