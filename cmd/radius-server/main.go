package main

import (
	"log"

	"github.com/qmish/2FA/internal/auth/providers"
	"github.com/qmish/2FA/internal/config"
	"github.com/qmish/2FA/internal/radius/server"
	"github.com/qmish/2FA/internal/radius/service"
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
	challengeRepo := postgres.NewChallengeRepository(db)
	loginRepo := postgres.NewLoginHistoryRepository(db)
	auditRepo := postgres.NewAuditRepository(db)

	registry := providers.NewRegistry()
	if cfg.ExpressMobileURL != "" && cfg.ExpressMobileKey != "" {
		express := providers.NewExpressMobileClient(cfg.ExpressMobileURL, cfg.ExpressMobileKey)
		registry.RegisterSMS(providers.DefaultSMSProvider, express)
	}
	secret := cfg.RadiusSecret
	if secret == "" {
		secret = "secret"
	}
	server.StartHealthServer(cfg.RadiusHealthAddr)
	svc := service.NewRadiusService(
		userRepo,
		challengeRepo,
		registry,
		loginRepo,
		auditRepo,
		cfg.AuthChallengeTTL,
	)
	if err := server.ListenAndServe(cfg.RadiusAddr, secret, svc); err != nil {
		log.Fatal(err)
	}
}
