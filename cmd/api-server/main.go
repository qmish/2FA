package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"time"

	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/qmish/2FA/internal/admin/auth"
	adminsvc "github.com/qmish/2FA/internal/admin/service"
	"github.com/qmish/2FA/internal/api/handlers"
	"github.com/qmish/2FA/internal/api/metrics"
	"github.com/qmish/2FA/internal/api/middlewares"
	"github.com/qmish/2FA/internal/api/router"
	authjwt "github.com/qmish/2FA/internal/auth/jwt"
	"github.com/qmish/2FA/internal/auth/ldap"
	"github.com/qmish/2FA/internal/auth/providers"
	"github.com/qmish/2FA/internal/auth/service"
	"github.com/qmish/2FA/internal/authz"
	"github.com/qmish/2FA/internal/config"
	lockoutsvc "github.com/qmish/2FA/internal/lockout/service"
	profilesvc "github.com/qmish/2FA/internal/profile/service"
	"github.com/qmish/2FA/internal/ratelimit"
	sessionsvc "github.com/qmish/2FA/internal/session/service"
	"github.com/qmish/2FA/internal/storage/postgres"
	"github.com/qmish/2FA/internal/ui"
	"github.com/qmish/2FA/pkg/logger"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	slog.SetDefault(logger.New())
	db, err := postgres.Open(cfg.DBURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	userRepo := postgres.NewUserRepository(db)
	inviteRepo := postgres.NewInviteRepository(db)
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
	otpSecretRepo := postgres.NewOTPSecretRepository(db)
	recoveryRepo := postgres.NewRecoveryCodeRepository(db)
	webauthnRepo := postgres.NewWebAuthnCredentialRepository(db)
	sessionRepo := postgres.NewSessionRepository(db)
	deviceRepo := postgres.NewDeviceRepository(db)
	lockoutRepo := postgres.NewLockoutRepository(db)
	authorizer := authz.NewAuthorizer(auditRepo, rolePermRepo)

	adminAuthService := auth.NewService(cfg.AdminJWTIssuer, []byte(cfg.AdminJWTSecret), cfg.AdminJWTTTL, userRepo)
	adminAuthHandler := handlers.NewAdminAuthHandler(adminAuthService)

	adminService := adminsvc.NewService(
		userRepo,
		inviteRepo,
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
		sessionRepo,
		lockoutRepo,
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

	jwtService := authjwt.NewService(cfg.JWTIssuer, []byte(cfg.JWTSecret), cfg.JWTTTL)
	authService := service.NewService(
		userRepo,
		challengeRepo,
		sessionRepo,
		registry,
		lockoutRepo,
		loginRepo,
		auditRepo,
		jwtService,
		cfg.AuthChallengeTTL,
		cfg.SessionTTL,
	)
	authService.WithPolicies(policyRepo, policyRuleRepo, userGroupRepo, groupPolicyRepo)
	authService.WithOTPSecrets(otpSecretRepo)
	authService.WithTOTPConfig(cfg.JWTIssuer, 6, 30)
	authService.WithInvites(inviteRepo)
	authService.WithRecoveryCodes(recoveryRepo)
	authService.WithDevices(deviceRepo)
	if cfg.WebAuthnRPID != "" && cfg.WebAuthnRPOrigin != "" && cfg.WebAuthnRPName != "" {
		wa, err := webauthnlib.New(&webauthnlib.Config{
			RPID:          cfg.WebAuthnRPID,
			RPDisplayName: cfg.WebAuthnRPName,
			RPOrigins:     []string{cfg.WebAuthnRPOrigin},
		})
		if err != nil {
			log.Printf("webauthn disabled: %v", err)
		} else {
			authService.WithWebAuthn(wa, webauthnRepo)
		}
	}
	if cfg.LDAPURL != "" {
		authService.WithLDAPAuth(ldap.NewClient(cfg.LDAPURL, cfg.LDAPTimeout))
	}
	var rateClient *ratelimit.RedisClient
	if cfg.RedisURL != "" {
		if client, err := ratelimit.NewRedisClient(cfg.RedisURL); err == nil {
			rateClient = client
		} else {
			log.Printf("redis disabled: %v", err)
		}
	}
	authHandler := handlers.NewAuthHandler(authService)
	healthHandler := handlers.NewHealthHandler(db, rateClient)
	sessionService := sessionsvc.NewServiceWithAudit(sessionRepo, auditRepo)
	sessionHandler := handlers.NewSessionHandler(sessionService)
	lockoutService := lockoutsvc.NewService(lockoutRepo)
	lockoutHandler := handlers.NewLockoutHandler(lockoutService)
	profileService := profilesvc.NewService(deviceRepo, loginRepo, otpSecretRepo, recoveryRepo, webauthnRepo)
	profileHandler := handlers.NewProfileHandler(profileService)
	uiHandler := ui.Handler()
	loginLimiter := middlewares.RateLimit(rateClient, "auth_login", cfg.AuthLoginLimit, time.Minute)
	verifyLimiter := middlewares.RateLimit(rateClient, "auth_verify", cfg.AuthVerifyLimit, time.Minute)

	adapter := adminTokenAdapter{svc: adminAuthService}
	routes := router.Routes{
		Auth:            authHandler,
		Health:          healthHandler,
		Sessions:        sessionHandler,
		Lockouts:        lockoutHandler,
		Profile:         profileHandler,
		UI:              uiHandler,
		Admin:           adminHandler,
		AdminAuth:       adminAuthHandler,
		AdminToken:      adapter,
		AuthRateLimit:   loginLimiter,
		VerifyRateLimit: verifyLimiter,
		AuthMiddleware:  middlewares.Auth(jwtService, sessionRepo, nil),
	}

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if _, err := challengeRepo.MarkExpired(context.Background(), time.Now()); err != nil {
				log.Printf("challenge cleanup failed: %v", err)
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cleared, err := lockoutRepo.ClearExpired(context.Background(), time.Now())
			if err != nil {
				metrics.Default.IncSystemError("db")
				log.Printf("lockout cleanup failed: %v", err)
				continue
			}
			metrics.Default.AddLockoutCleared(cleared)
		}
	}()

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
