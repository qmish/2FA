package router

import (
    "net/http"

    "github.com/qmish/2FA/internal/api/handlers"
)

type Routes struct {
    Auth *handlers.AuthHandler
}

func New(r Routes) http.Handler {
    mux := http.NewServeMux()
    mux.HandleFunc("/api/v1/auth/login", r.Auth.Login)
    mux.HandleFunc("/api/v1/auth/verify", r.Auth.Verify)
    mux.HandleFunc("/api/v1/auth/refresh", r.Auth.Refresh)
    mux.HandleFunc("/api/v1/auth/logout", r.Auth.Logout)
    return mux
}
