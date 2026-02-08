package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
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
	"github.com/qmish/2FA/internal/observability"
	profilesvc "github.com/qmish/2FA/internal/profile/service"
	"github.com/qmish/2FA/internal/ratelimit"
	sessionsvc "github.com/qmish/2FA/internal/session/service"
	"github.com/qmish/2FA/internal/storage/postgres"
	"github.com/qmish/2FA/internal/ui"
	"github.com/qmish/2FA/pkg/logger"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	traceShutdown, err := observability.InitTracing(ctx, cfg)
	if err != nil {
		log.Printf("tracing disabled: %v", err)
	} else {
		defer func() {
			if err := traceShutdown(context.Background()); err != nil {
				log.Printf("tracing shutdown error: %v", err)
			}
		}()
	}
	slog.SetDefault(logger.New())
	db, err := postgres.OpenWithConfig(cfg.DBURL, postgres.PoolConfig{
		MaxOpenConns:    cfg.DBMaxOpenConns,
		MaxIdleConns:    cfg.DBMaxIdleConns,
		ConnMaxLifetime: cfg.DBConnMaxLifetime,
		ConnMaxIdleTime: cfg.DBConnMaxIdleTime,
		PingTimeout:     cfg.DBConnectTimeout,
	})
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
	webauthnSessionRepo := postgres.NewWebAuthnSessionRepository(db)
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
	registry.ConfigureRetry(cfg.ProviderMaxRetries, cfg.ProviderBreakerFailures, cfg.ProviderBreakerTimeout)
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
			authService.WithWebAuthn(wa, webauthnRepo, webauthnSessionRepo)
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
	healthHandler := handlers.NewHealthHandler(db, rateClient, cfg.DBQueryTimeout)
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
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := challengeRepo.MarkExpired(ctx, time.Now()); err != nil {
					log.Printf("challenge cleanup failed: %v", err)
				}
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleared, err := lockoutRepo.ClearExpired(ctx, time.Now())
				if err != nil {
					metrics.Default.IncSystemError("db")
					log.Printf("lockout cleanup failed: %v", err)
					continue
				}
				metrics.Default.AddLockoutCleared(cleared)
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleared, err := webauthnSessionRepo.DeleteExpired(ctx, time.Now())
				if err != nil {
					metrics.Default.IncSystemError("db")
					log.Printf("webauthn sessions cleanup failed: %v", err)
					continue
				}
				metrics.Default.AddWebauthnSessionsCleared(cleared)
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats := db.Stats()
				metrics.Default.SetDBPoolStats(metrics.DBPoolStats{
					OpenConns:      stats.OpenConnections,
					InUse:          stats.InUse,
					Idle:           stats.Idle,
					WaitCount:      stats.WaitCount,
					WaitDurationMs: stats.WaitDuration.Milliseconds(),
					MaxOpenConns:   stats.MaxOpenConnections,
				})
			}
		}
	}()

	addr := ":" + cfg.HTTPPort
	log.Printf("api-server listening on %s", addr)
	server := &http.Server{
		Addr:    addr,
		Handler: router.New(routes),
	}
	if err := serveHTTPWithShutdown(ctx, server, 10*time.Second); err != nil {
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

func serveHTTPWithShutdown(ctx context.Context, server *http.Server, timeout time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		err := <-errCh
		if err == nil || err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
