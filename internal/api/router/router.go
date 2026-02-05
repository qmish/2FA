package router

import (
    "net/http"

    "github.com/qmish/2FA/internal/api/handlers"
    "github.com/qmish/2FA/internal/api/middlewares"
)

type Routes struct {
    Auth *handlers.AuthHandler
    Admin *handlers.AdminHandler
}

func New(r Routes) http.Handler {
    mux := http.NewServeMux()
    mux.HandleFunc("/healthz", handlers.Health)
    mux.HandleFunc("/metrics", handlers.Metrics)
    mux.HandleFunc("/api/v1/auth/login", r.Auth.Login)
    mux.HandleFunc("/api/v1/auth/verify", r.Auth.Verify)
    mux.HandleFunc("/api/v1/auth/refresh", r.Auth.Refresh)
    mux.HandleFunc("/api/v1/auth/logout", r.Auth.Logout)
    mux.HandleFunc("/api/v1/admin/users", r.Admin.ListUsers)
    mux.HandleFunc("/api/v1/admin/policies", r.Admin.ListPolicies)
    mux.HandleFunc("/api/v1/admin/radius/clients", r.Admin.ListRadiusClients)
    mux.HandleFunc("/api/v1/admin/audit/events", r.Admin.ListAuditEvents)
    mux.HandleFunc("/api/v1/admin/logins", r.Admin.ListLoginHistory)
    mux.HandleFunc("/api/v1/admin/radius/requests", r.Admin.ListRadiusRequests)
    return middlewares.RequestID(mux)
}
