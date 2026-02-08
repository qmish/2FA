package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/qmish/2FA/internal/auth/providers"
	"github.com/qmish/2FA/internal/config"
	"github.com/qmish/2FA/internal/radius/server"
	"github.com/qmish/2FA/internal/radius/service"
	"github.com/qmish/2FA/internal/storage/postgres"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
	challengeRepo := postgres.NewChallengeRepository(db)
	loginRepo := postgres.NewLoginHistoryRepository(db)
	auditRepo := postgres.NewAuditRepository(db)

	registry := providers.NewRegistry()
	registry.ConfigureRetry(cfg.ProviderMaxRetries, cfg.ProviderBreakerFailures, cfg.ProviderBreakerTimeout)
	if cfg.ExpressMobileURL != "" && cfg.ExpressMobileKey != "" {
		express := providers.NewExpressMobileClient(cfg.ExpressMobileURL, cfg.ExpressMobileKey)
		registry.RegisterSMS(providers.DefaultSMSProvider, express)
	}
	secret := cfg.RadiusSecret
	if secret == "" {
		secret = "secret"
	}
	healthServer := server.StartHealthServer(cfg.RadiusHealthAddr)
	svc := service.NewRadiusService(
		userRepo,
		challengeRepo,
		registry,
		loginRepo,
		auditRepo,
		cfg.AuthChallengeTTL,
	)
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServeWithContext(ctx, cfg.RadiusAddr, secret, svc)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			log.Fatal(err)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if healthServer != nil {
			if err := healthServer.Shutdown(shutdownCtx); err != nil {
				log.Printf("radius health shutdown error: %v", err)
			}
		}
		if err := <-errCh; err != nil {
			log.Printf("radius server shutdown error: %v", err)
		}
	}
}
