package main

import (
    "log"
    "net/http"

    "github.com/qmish/2FA/internal/admin/auth"
    adminsvc "github.com/qmish/2FA/internal/admin/service"
    "github.com/qmish/2FA/internal/api/handlers"
    "github.com/qmish/2FA/internal/api/middlewares"
    "github.com/qmish/2FA/internal/api/router"
    "github.com/qmish/2FA/internal/auth/providers"
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
    policyRepo := postgres.NewPolicyRepository(db)
    policyRuleRepo := postgres.NewPolicyRuleRepository(db)
    radiusClientRepo := postgres.NewRadiusClientRepository(db)
    groupRepo := postgres.NewGroupRepository(db)
    userGroupRepo := postgres.NewUserGroupRepository(db)
    groupPolicyRepo := postgres.NewGroupPolicyRepository(db)
    auditRepo := postgres.NewAuditRepository(db)
    loginRepo := postgres.NewLoginHistoryRepository(db)
    radiusReqRepo := postgres.NewRadiusRequestRepository(db)
    rolePermRepo := postgres.NewRolePermissionRepository(db)
    challengeRepo := postgres.NewChallengeRepository(db)
    sessionRepo := postgres.NewSessionRepository(db)
    authorizer := authz.NewAuthorizer(auditRepo, rolePermRepo)

    adminAuthService := auth.NewService(cfg.AdminJWTIssuer, []byte(cfg.AdminJWTSecret), cfg.AdminJWTTTL, userRepo)
    adminAuthHandler := handlers.NewAdminAuthHandler(adminAuthService)

    adminService := adminsvc.NewService(
        userRepo,
        policyRepo,
        policyRuleRepo,
        radiusClientRepo,
        rolePermRepo,
        groupRepo,
        userGroupRepo,
        groupPolicyRepo,
        auditRepo,
        loginRepo,
        radiusReqRepo,
    )
    adminHandler := handlers.NewAdminHandler(adminService, authorizer)

    registry := providers.NewRegistry()
    if cfg.ExpressMobileURL != "" && cfg.ExpressMobileKey != "" {
        express := providers.NewExpressMobileClient(cfg.ExpressMobileURL, cfg.ExpressMobileKey)
        registry.RegisterSMS(providers.DefaultSMSProvider, express)
        registry.RegisterCall(providers.DefaultCallProvider, express)
    }
    if cfg.FCMServerKey != "" {
        fcm := providers.NewFCMClient(cfg.FCMServerKey)
        registry.RegisterPush(providers.DefaultPushProvider, fcm)
    }

    authService := service.NewService(
        userRepo,
        challengeRepo,
        sessionRepo,
        registry,
        cfg.AuthChallengeTTL,
        cfg.SessionTTL,
    )
    authHandler := handlers.NewAuthHandler(authService)

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
