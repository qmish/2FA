package main

import (
    "context"
    "log"
    "os"

    "github.com/qmish/2FA/internal/radius/server"
    "github.com/qmish/2FA/internal/radius/service"
)

func main() {
    addr := os.Getenv("RADIUS_ADDR")
    if addr == "" {
        addr = ":1812"
    }
    svc := service.NewRadiusService(
        func(_ context.Context, username, password string) bool { return true },
        func(_ context.Context, username string) bool { return true },
    )
    if err := server.ListenAndServe(addr, svc); err != nil {
        log.Fatal(err)
    }
}
