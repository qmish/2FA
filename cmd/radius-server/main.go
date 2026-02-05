package main

import (
    "context"
    "log"

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
    secret := cfg.RadiusSecret
    if secret == "" {
        secret = "secret"
    }
    svc := service.NewRadiusService(
        func(_ context.Context, username, password string) bool { return true },
        func(_ context.Context, username string) bool { return true },
    )
    if err := server.ListenAndServe(cfg.RadiusAddr, secret, svc); err != nil {
        log.Fatal(err)
    }
}
