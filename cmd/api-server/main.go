package main

import (
    "log"
    "net/http"

    "github.com/qmish/2FA/internal/admin/auth"
    adminsvc "github.com/qmish/2FA/internal/admin/service"
    "github.com/qmish/2FA/internal/api/handlers"
    "github.com/qmish/2FA/internal/api/middlewares"
    "github.com/qmish/2FA/internal/api/router"
    "github.com/qmish/2FA/internal/auth/service"
    "github.com/qmish/2FA/internal/authz"
    "github.com/qmish/2FA/internal/config"
    "github.com/qmish/2FA/internal/storage/postgres"
)

func main() {
    cfg, err := config.Load()
    if err != nil {
        log.Fatal(err)
    }
    db, err := postgres.Open(cfg.DBURL)
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    userRepo := postgres.NewUserRepository(db)
    auditRepo := postgres.NewAuditRepository(db)
    authorizer := authz.NewAuthorizer(auditRepo)

    adminAuthService := auth.NewService(cfg.AdminJWTIssuer, []byte(cfg.AdminJWTSecret), cfg.AdminJWTTTL, userRepo)
    adminAuthHandler := handlers.NewAdminAuthHandler(adminAuthService)

    adminHandler := handlers.NewAdminHandler(adminsvc.StubService{}, authorizer)
    authHandler := handlers.NewAuthHandler(service.StubAuthService{})

    adapter := adminTokenAdapter{svc: adminAuthService}
    routes := router.Routes{
        Auth:       authHandler,
        Admin:      adminHandler,
        AdminAuth:  adminAuthHandler,
        AdminToken: adapter,
    }

    addr := ":" + cfg.HTTPPort
    log.Printf("api-server listening on %s", addr)
    if err := http.ListenAndServe(addr, router.New(routes)); err != nil {
        log.Fatal(err)
    }
}

type adminTokenAdapter struct {
    svc *auth.Service
}

func (a adminTokenAdapter) ParseClaims(token string) (*middlewares.AdminClaims, error) {
    claims, err := a.svc.ParseClaims(token)
    if err != nil {
        return nil, err
    }
    return &middlewares.AdminClaims{UserID: claims.Subject, Role: claims.Role}, nil
}
