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
    mux.Handle("/api/v1/admin/policies", adminAuth(http.HandlerFunc(r.Admin.ListPolicies)))
    mux.Handle("/api/v1/admin/radius/clients", adminAuth(http.HandlerFunc(r.Admin.ListRadiusClients)))
    mux.Handle("/api/v1/admin/audit/events", adminAuth(http.HandlerFunc(r.Admin.ListAuditEvents)))
    mux.Handle("/api/v1/admin/logins", adminAuth(http.HandlerFunc(r.Admin.ListLoginHistory)))
    mux.Handle("/api/v1/admin/radius/requests", adminAuth(http.HandlerFunc(r.Admin.ListRadiusRequests)))
    return middlewares.RequestID(mux)
}
