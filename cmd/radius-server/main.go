package main

import (
    "context"
    "log"

    "github.com/qmish/2FA/internal/config"
    "github.com/qmish/2FA/internal/radius/server"
    "github.com/qmish/2FA/internal/radius/service"
)

func main() {
    cfg, err := config.Load()
    if err != nil {
        log.Fatal(err)
    }
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
