package router

import (
	"net/http"

	"github.com/qmish/2FA/internal/api/handlers"
	"github.com/qmish/2FA/internal/api/middlewares"
)

type Routes struct {
	Auth            *handlers.AuthHandler
	Health          *handlers.HealthHandler
	Sessions        *handlers.SessionHandler
	Lockouts        *handlers.LockoutHandler
	UI              http.Handler
	Admin           *handlers.AdminHandler
	AdminAuth       *handlers.AdminAuthHandler
	Profile         *handlers.ProfileHandler
	AdminToken      middlewares.AdminTokenValidator
	AuthRateLimit   func(http.Handler) http.Handler
	VerifyRateLimit func(http.Handler) http.Handler
	AuthMiddleware  func(http.Handler) http.Handler
}

func New(r Routes) http.Handler {
	mux := http.NewServeMux()
	if r.UI != nil {
		mux.Handle("/ui/", http.StripPrefix("/ui/", r.UI))
		mux.Handle("/ui", http.RedirectHandler("/ui/", http.StatusMovedPermanently))
	}
	if r.Health != nil {
		mux.HandleFunc("/healthz", r.Health.Health)
	} else {
		mux.HandleFunc("/healthz", handlers.Health)
	}
	mux.HandleFunc("/metrics", handlers.Metrics)
	var loginHandler http.Handler = http.HandlerFunc(r.Auth.Login)
	if r.AuthRateLimit != nil {
		loginHandler = r.AuthRateLimit(loginHandler)
	}
	var verifyHandler http.Handler = http.HandlerFunc(r.Auth.Verify)
	if r.VerifyRateLimit != nil {
		verifyHandler = r.VerifyRateLimit(verifyHandler)
	}
	mux.Handle("/api/v1/auth/login", loginHandler)
	mux.Handle("/api/v1/auth/register", http.HandlerFunc(r.Auth.Register))
	mux.Handle("/api/v1/auth/verify", verifyHandler)
	mux.HandleFunc("/api/v1/auth/refresh", r.Auth.Refresh)
	var logoutHandler http.Handler = http.HandlerFunc(r.Auth.Logout)
	if r.AuthMiddleware != nil {
		logoutHandler = r.AuthMiddleware(logoutHandler)
	}
	mux.Handle("/api/v1/auth/logout", logoutHandler)
	if r.AuthMiddleware != nil {
		mux.Handle("/api/v1/auth/totp/setup", r.AuthMiddleware(http.HandlerFunc(r.Auth.SetupTOTP)))
		mux.Handle("/api/v1/auth/totp/disable", r.AuthMiddleware(http.HandlerFunc(r.Auth.DisableTOTP)))
		mux.Handle("/api/v1/auth/recovery/generate", r.AuthMiddleware(http.HandlerFunc(r.Auth.GenerateRecoveryCodes)))
	}
	if r.Profile != nil && r.AuthMiddleware != nil {
		mux.Handle("/api/v1/profile/devices", r.AuthMiddleware(http.HandlerFunc(r.Profile.ListDevices)))
		mux.Handle("/api/v1/profile/logins", r.AuthMiddleware(http.HandlerFunc(r.Profile.ListLoginHistory)))
	}
	if r.Sessions != nil {
		var sessionsList http.Handler = http.HandlerFunc(r.Sessions.List)
		var sessionsCurrent http.Handler = http.HandlerFunc(r.Sessions.Current)
		var sessionsRevoke http.Handler = http.HandlerFunc(r.Sessions.Revoke)
		var sessionsRevokeAll http.Handler = http.HandlerFunc(r.Sessions.RevokeAll)
		if r.AuthMiddleware != nil {
			sessionsList = r.AuthMiddleware(sessionsList)
			sessionsCurrent = r.AuthMiddleware(sessionsCurrent)
			sessionsRevoke = r.AuthMiddleware(sessionsRevoke)
			sessionsRevokeAll = r.AuthMiddleware(sessionsRevokeAll)
		}
		mux.Handle("/api/v1/sessions", sessionsList)
		mux.Handle("/api/v1/sessions/current", sessionsCurrent)
		mux.Handle("/api/v1/sessions/revoke", sessionsRevoke)
		mux.Handle("/api/v1/sessions/revoke_all", sessionsRevokeAll)
	}
	if r.Lockouts != nil {
		var lockoutCurrent http.Handler = http.HandlerFunc(r.Lockouts.Current)
		if r.AuthMiddleware != nil {
			lockoutCurrent = r.AuthMiddleware(lockoutCurrent)
		}
		mux.Handle("/api/v1/lockouts/current", lockoutCurrent)
	}
	mux.HandleFunc("/api/v1/admin/auth/login", r.AdminAuth.Login)

	adminAuth := middlewares.AdminAuth(r.AdminToken)
	mux.Handle("/api/v1/admin/users", adminAuth(http.HandlerFunc(r.Admin.ListUsers)))
	mux.Handle("/api/v1/admin/users/create", adminAuth(http.HandlerFunc(r.Admin.CreateUser)))
	mux.Handle("/api/v1/admin/users/import", adminAuth(http.HandlerFunc(r.Admin.ImportUsers)))
	mux.Handle("/api/v1/admin/users/export", adminAuth(http.HandlerFunc(r.Admin.ExportUsers)))
	mux.Handle("/api/v1/admin/users/update", adminAuth(http.HandlerFunc(r.Admin.UpdateUser)))
	mux.Handle("/api/v1/admin/users/delete", adminAuth(http.HandlerFunc(r.Admin.DeleteUser)))
	mux.Handle("/api/v1/admin/policies", adminAuth(http.HandlerFunc(r.Admin.ListPolicies)))
	mux.Handle("/api/v1/admin/policies/create", adminAuth(http.HandlerFunc(r.Admin.CreatePolicy)))
	mux.Handle("/api/v1/admin/policies/update", adminAuth(http.HandlerFunc(r.Admin.UpdatePolicy)))
	mux.Handle("/api/v1/admin/policies/delete", adminAuth(http.HandlerFunc(r.Admin.DeletePolicy)))
	mux.Handle("/api/v1/admin/radius/clients", adminAuth(http.HandlerFunc(r.Admin.ListRadiusClients)))
	mux.Handle("/api/v1/admin/radius/clients/create", adminAuth(http.HandlerFunc(r.Admin.CreateRadiusClient)))
	mux.Handle("/api/v1/admin/radius/clients/update", adminAuth(http.HandlerFunc(r.Admin.UpdateRadiusClient)))
	mux.Handle("/api/v1/admin/radius/clients/delete", adminAuth(http.HandlerFunc(r.Admin.DeleteRadiusClient)))
	mux.Handle("/api/v1/admin/role-permissions", adminAuth(http.HandlerFunc(r.Admin.GetRolePermissions)))
	mux.Handle("/api/v1/admin/role-permissions/update", adminAuth(http.HandlerFunc(r.Admin.SetRolePermissions)))
	mux.Handle("/api/v1/admin/groups", adminAuth(http.HandlerFunc(r.Admin.ListGroups)))
	mux.Handle("/api/v1/admin/groups/create", adminAuth(http.HandlerFunc(r.Admin.CreateGroup)))
	mux.Handle("/api/v1/admin/groups/update", adminAuth(http.HandlerFunc(r.Admin.UpdateGroup)))
	mux.Handle("/api/v1/admin/groups/delete", adminAuth(http.HandlerFunc(r.Admin.DeleteGroup)))
	mux.Handle("/api/v1/admin/groups/members", adminAuth(http.HandlerFunc(r.Admin.ListGroupMembers)))
	mux.Handle("/api/v1/admin/groups/members/add", adminAuth(http.HandlerFunc(r.Admin.AddGroupMember)))
	mux.Handle("/api/v1/admin/groups/members/remove", adminAuth(http.HandlerFunc(r.Admin.RemoveGroupMember)))
	mux.Handle("/api/v1/admin/groups/policy", adminAuth(http.HandlerFunc(r.Admin.SetGroupPolicy)))
	mux.Handle("/api/v1/admin/groups/policy/clear", adminAuth(http.HandlerFunc(r.Admin.ClearGroupPolicy)))
	mux.Handle("/api/v1/admin/invites/create", adminAuth(http.HandlerFunc(r.Admin.CreateInvite)))
	mux.Handle("/api/v1/admin/audit/events", adminAuth(http.HandlerFunc(r.Admin.ListAuditEvents)))
	mux.Handle("/api/v1/admin/audit/export", adminAuth(http.HandlerFunc(r.Admin.ExportAuditEvents)))
	mux.Handle("/api/v1/admin/logins", adminAuth(http.HandlerFunc(r.Admin.ListLoginHistory)))
	mux.Handle("/api/v1/admin/radius/requests", adminAuth(http.HandlerFunc(r.Admin.ListRadiusRequests)))
	mux.Handle("/api/v1/admin/sessions", adminAuth(http.HandlerFunc(r.Admin.ListSessions)))
	mux.Handle("/api/v1/admin/sessions/revoke", adminAuth(http.HandlerFunc(r.Admin.RevokeSession)))
	mux.Handle("/api/v1/admin/sessions/revoke_user", adminAuth(http.HandlerFunc(r.Admin.RevokeUserSessions)))
	mux.Handle("/api/v1/admin/lockouts", adminAuth(http.HandlerFunc(r.Admin.ListLockouts)))
	mux.Handle("/api/v1/admin/lockouts/clear", adminAuth(http.HandlerFunc(r.Admin.ClearLockouts)))
	return middlewares.RequestID(middlewares.Metrics(middlewares.RequestLogger(mux)))
}
