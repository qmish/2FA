package config

import (
    "os"
    "testing"
    "time"
)

func TestLoadFromEnv(t *testing.T) {
    t.Setenv("HTTP_PORT", "9090")
    t.Setenv("ADMIN_JWT_TTL", "10m")

    cfg := LoadFromEnv()
    if cfg.HTTPPort != "9090" {
        t.Fatalf("expected HTTP_PORT 9090, got %s", cfg.HTTPPort)
    }
    if cfg.AdminJWTTTL != 10*time.Minute {
        t.Fatalf("expected TTL 10m, got %s", cfg.AdminJWTTTL)
    }
}

func TestLoadFromFile(t *testing.T) {
    content := []byte("http_port: \"8081\"\nadmin_jwt_ttl: 5m\n")
    file, err := os.CreateTemp("", "config-*.yaml")
    if err != nil {
        t.Fatalf("temp file: %v", err)
    }
    defer os.Remove(file.Name())
    if _, err := file.Write(content); err != nil {
        t.Fatalf("write: %v", err)
    }
    if err := file.Close(); err != nil {
        t.Fatalf("close: %v", err)
    }

    cfg, err := LoadFromFile(file.Name())
    if err != nil {
        t.Fatalf("load: %v", err)
    }
    if cfg.HTTPPort != "8081" {
        t.Fatalf("expected HTTP_PORT 8081, got %s", cfg.HTTPPort)
    }
    if cfg.AdminJWTTTL != 5*time.Minute {
        t.Fatalf("expected TTL 5m, got %s", cfg.AdminJWTTTL)
    }
}
