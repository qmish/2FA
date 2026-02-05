package router

import (
    "net/http"

    "github.com/qmish/2FA/internal/api/handlers"
    "github.com/qmish/2FA/internal/api/middlewares"
)

type Routes struct {
    Auth *handlers.AuthHandler
    Admin *handlers.AdminHandler
    AdminAuth *handlers.AdminAuthHandler
    AdminToken middlewares.AdminTokenValidator
}

func New(r Routes) http.Handler {
    mux := http.NewServeMux()
    mux.HandleFunc("/healthz", handlers.Health)
    mux.HandleFunc("/metrics", handlers.Metrics)
    mux.HandleFunc("/api/v1/auth/login", r.Auth.Login)
    mux.HandleFunc("/api/v1/auth/verify", r.Auth.Verify)
    mux.HandleFunc("/api/v1/auth/refresh", r.Auth.Refresh)
    mux.HandleFunc("/api/v1/auth/logout", r.Auth.Logout)
    mux.HandleFunc("/api/v1/admin/auth/login", r.AdminAuth.Login)

    adminAuth := middlewares.AdminAuth(r.AdminToken)
    mux.Handle("/api/v1/admin/users", adminAuth(http.HandlerFunc(r.Admin.ListUsers)))
    mux.Handle("/api/v1/admin/users/create", adminAuth(http.HandlerFunc(r.Admin.CreateUser)))
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
    mux.Handle("/api/v1/admin/audit/events", adminAuth(http.HandlerFunc(r.Admin.ListAuditEvents)))
    mux.Handle("/api/v1/admin/logins", adminAuth(http.HandlerFunc(r.Admin.ListLoginHistory)))
    mux.Handle("/api/v1/admin/radius/requests", adminAuth(http.HandlerFunc(r.Admin.ListRadiusRequests)))
    return middlewares.RequestID(mux)
}
