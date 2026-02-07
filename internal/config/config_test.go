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

func TestValidateWebAuthnConfig(t *testing.T) {
	cfg := Defaults()
	cfg.DBURL = "postgres://user:pass@localhost:5432/2fa?sslmode=disable"
	cfg.JWTSecret = "secret"
	cfg.AdminJWTSecret = "admin"
	cfg.RadiusSecret = "radius"
	cfg.RedisURL = "redis://localhost:6379/0"
	cfg.WebAuthnRPID = "2fa.local"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for incomplete webauthn config")
	}

	cfg.WebAuthnRPOrigin = "https://2fa.local"
	cfg.WebAuthnRPName = "2FA"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateWebAuthnOriginScheme(t *testing.T) {
	cfg := Defaults()
	cfg.DBURL = "postgres://user:pass@localhost:5432/2fa?sslmode=disable"
	cfg.JWTSecret = "secret"
	cfg.AdminJWTSecret = "admin"
	cfg.RadiusSecret = "radius"
	cfg.RedisURL = "redis://localhost:6379/0"
	cfg.WebAuthnRPID = "2fa.local"
	cfg.WebAuthnRPName = "2FA"
	cfg.WebAuthnRPOrigin = "http://example.com"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for non-https origin")
	}

	cfg.WebAuthnRPOrigin = "https://2fa.local"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg.WebAuthnRPID = "localhost"
	cfg.WebAuthnRPOrigin = "http://localhost:8080"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateWebAuthnOriginHostMatchesRPID(t *testing.T) {
	cfg := Defaults()
	cfg.DBURL = "postgres://user:pass@localhost:5432/2fa?sslmode=disable"
	cfg.JWTSecret = "secret"
	cfg.AdminJWTSecret = "admin"
	cfg.RadiusSecret = "radius"
	cfg.RedisURL = "redis://localhost:6379/0"
	cfg.WebAuthnRPID = "example.com"
	cfg.WebAuthnRPName = "2FA"

	cfg.WebAuthnRPOrigin = "https://example.com"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg.WebAuthnRPOrigin = "https://auth.example.com"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg.WebAuthnRPOrigin = "https://example.org"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for mismatched origin host")
	}

	cfg.WebAuthnRPOrigin = "https://example.com.evil.com"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for invalid suffix")
	}
}

func TestValidateRedisRequiredWhenRateLimitEnabled(t *testing.T) {
	cfg := Defaults()
	cfg.DBURL = "postgres://user:pass@localhost:5432/2fa?sslmode=disable"
	cfg.JWTSecret = "secret"
	cfg.AdminJWTSecret = "admin"
	cfg.RadiusSecret = "radius"
	cfg.RedisURL = ""

	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for missing redis_url")
	}

	cfg.RedisURL = "redis://localhost:6379/0"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg.RedisURL = ""
	cfg.AuthLoginLimit = 0
	cfg.AuthVerifyLimit = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRejectsDefaultSecrets(t *testing.T) {
	cfg := Defaults()
	cfg.DBURL = "postgres://user:pass@localhost:5432/2fa?sslmode=disable"
	cfg.RedisURL = "redis://localhost:6379/0"

	cfg.JWTSecret = "CHANGE_ME"
	cfg.AdminJWTSecret = "admin"
	cfg.RadiusSecret = "radius"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for default jwt_secret")
	}

	cfg.JWTSecret = "secret"
	cfg.AdminJWTSecret = "CHANGE_ME"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for default admin_jwt_secret")
	}

	cfg.AdminJWTSecret = "admin"
	cfg.RadiusSecret = "CHANGE_ME"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for default radius_secret")
	}

	cfg.RadiusSecret = "radius"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRejectsNegativeRateLimits(t *testing.T) {
	cfg := Defaults()
	cfg.DBURL = "postgres://user:pass@localhost:5432/2fa?sslmode=disable"
	cfg.JWTSecret = "secret"
	cfg.AdminJWTSecret = "admin"
	cfg.RadiusSecret = "radius"
	cfg.RedisURL = "redis://localhost:6379/0"

	cfg.AuthLoginLimit = -1
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for negative auth_login_limit")
	}

	cfg.AuthLoginLimit = 10
	cfg.AuthVerifyLimit = -5
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for negative auth_verify_limit")
	}

	cfg.AuthVerifyLimit = 10
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRejectsEmptyJWTIssuer(t *testing.T) {
	cfg := Defaults()
	cfg.DBURL = "postgres://user:pass@localhost:5432/2fa?sslmode=disable"
	cfg.JWTSecret = "secret"
	cfg.AdminJWTSecret = "admin"
	cfg.RadiusSecret = "radius"
	cfg.RedisURL = "redis://localhost:6379/0"

	cfg.JWTIssuer = ""
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for empty jwt_issuer")
	}

	cfg.JWTIssuer = "2fa"
	cfg.AdminJWTIssuer = ""
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for empty admin_jwt_issuer")
	}

	cfg.AdminJWTIssuer = "2fa"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRedisURLFormat(t *testing.T) {
	cfg := Defaults()
	cfg.DBURL = "postgres://user:pass@localhost:5432/2fa?sslmode=disable"
	cfg.JWTSecret = "secret"
	cfg.AdminJWTSecret = "admin"
	cfg.RadiusSecret = "radius"
	cfg.AuthLoginLimit = 0
	cfg.AuthVerifyLimit = 0

	cfg.RedisURL = "localhost:6379"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for invalid redis_url")
	}

	cfg.RedisURL = "redis://localhost:6379/0"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
