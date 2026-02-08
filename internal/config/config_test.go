package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("HTTP_PORT", "9090")
	t.Setenv("ADMIN_JWT_TTL", "10m")
	t.Setenv("RADIUS_HEALTH_ADDR", "127.0.0.1:18090")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel:4318")
	t.Setenv("OTEL_SERVICE_NAME", "2fa-api")
	t.Setenv("OTEL_SAMPLE_RATIO", "0.5")
	t.Setenv("PROVIDER_MAX_RETRIES", "3")
	t.Setenv("PROVIDER_BREAKER_FAILURES", "4")
	t.Setenv("PROVIDER_BREAKER_TIMEOUT", "45s")

	cfg := LoadFromEnv()
	if cfg.HTTPPort != "9090" {
		t.Fatalf("expected HTTP_PORT 9090, got %s", cfg.HTTPPort)
	}
	if cfg.AdminJWTTTL != 10*time.Minute {
		t.Fatalf("expected TTL 10m, got %s", cfg.AdminJWTTTL)
	}
	if cfg.RadiusHealthAddr != "127.0.0.1:18090" {
		t.Fatalf("expected RADIUS_HEALTH_ADDR 127.0.0.1:18090, got %s", cfg.RadiusHealthAddr)
	}
	if cfg.OTelEndpoint != "http://otel:4318" {
		t.Fatalf("expected OTEL_EXPORTER_OTLP_ENDPOINT http://otel:4318, got %s", cfg.OTelEndpoint)
	}
	if cfg.OTelServiceName != "2fa-api" {
		t.Fatalf("expected OTEL_SERVICE_NAME 2fa-api, got %s", cfg.OTelServiceName)
	}
	if cfg.OTelSampleRatio != 0.5 {
		t.Fatalf("expected OTEL_SAMPLE_RATIO 0.5, got %v", cfg.OTelSampleRatio)
	}
	if cfg.ProviderMaxRetries != 3 {
		t.Fatalf("expected PROVIDER_MAX_RETRIES 3, got %v", cfg.ProviderMaxRetries)
	}
	if cfg.ProviderBreakerFailures != 4 {
		t.Fatalf("expected PROVIDER_BREAKER_FAILURES 4, got %v", cfg.ProviderBreakerFailures)
	}
	if cfg.ProviderBreakerTimeout != 45*time.Second {
		t.Fatalf("expected PROVIDER_BREAKER_TIMEOUT 45s, got %v", cfg.ProviderBreakerTimeout)
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

func TestValidateRadiusHealthAddr(t *testing.T) {
	cfg := Defaults()
	cfg.DBURL = "postgres://user:pass@localhost:5432/2fa?sslmode=disable"
	cfg.JWTSecret = "secret"
	cfg.AdminJWTSecret = "admin"
	cfg.RadiusSecret = "radius"
	cfg.RedisURL = "redis://localhost:6379/0"

	cfg.RadiusHealthAddr = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for invalid radius_health_addr")
	}

	cfg.RadiusHealthAddr = "127.0.0.1:8090"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateOTelConfig(t *testing.T) {
	cfg := Defaults()
	cfg.DBURL = "postgres://user:pass@localhost:5432/2fa?sslmode=disable"
	cfg.JWTSecret = "secret"
	cfg.AdminJWTSecret = "admin"
	cfg.RadiusSecret = "radius"
	cfg.RedisURL = "redis://localhost:6379/0"

	cfg.OTelEndpoint = "otel:4318"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for invalid otel endpoint")
	}

	cfg.OTelEndpoint = "http://otel:4318"
	cfg.OTelServiceName = ""
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for empty otel service name")
	}

	cfg.OTelServiceName = "2fa"
	cfg.OTelSampleRatio = 1.5
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for invalid otel sample ratio")
	}

	cfg.OTelSampleRatio = 0.5
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateProviderRetryConfig(t *testing.T) {
	cfg := Defaults()
	cfg.DBURL = "postgres://user:pass@localhost:5432/2fa?sslmode=disable"
	cfg.JWTSecret = "secret"
	cfg.AdminJWTSecret = "admin"
	cfg.RadiusSecret = "radius"
	cfg.RedisURL = "redis://localhost:6379/0"

	cfg.ProviderMaxRetries = -1
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for provider_max_retries")
	}

	cfg.ProviderMaxRetries = 2
	cfg.ProviderBreakerFailures = -2
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for provider_breaker_failures")
	}

	cfg.ProviderBreakerFailures = 2
	cfg.ProviderBreakerTimeout = 0
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for provider_breaker_timeout")
	}

	cfg.ProviderBreakerTimeout = 15 * time.Second
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
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

func TestValidateDBURLFormat(t *testing.T) {
	cfg := Defaults()
	cfg.DBURL = "localhost:5432/2fa"
	cfg.JWTSecret = "secret"
	cfg.AdminJWTSecret = "admin"
	cfg.RadiusSecret = "radius"
	cfg.RedisURL = "redis://localhost:6379/0"

	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for invalid db_url")
	}

	cfg.DBURL = "postgres://user:pass@localhost:5432/2fa?sslmode=disable"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePorts(t *testing.T) {
	cfg := Defaults()
	cfg.DBURL = "postgres://user:pass@localhost:5432/2fa?sslmode=disable"
	cfg.JWTSecret = "secret"
	cfg.AdminJWTSecret = "admin"
	cfg.RadiusSecret = "radius"
	cfg.RedisURL = "redis://localhost:6379/0"

	cfg.HTTPPort = "0"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for http_port")
	}

	cfg.HTTPPort = "8080"
	cfg.RadiusAddr = "1812"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for radius_addr")
	}

	cfg.RadiusAddr = ":1812"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateLDAPURLScheme(t *testing.T) {
	cfg := Defaults()
	cfg.DBURL = "postgres://user:pass@localhost:5432/2fa?sslmode=disable"
	cfg.JWTSecret = "secret"
	cfg.AdminJWTSecret = "admin"
	cfg.RadiusSecret = "radius"
	cfg.RedisURL = "redis://localhost:6379/0"

	cfg.LDAPURL = "http://ldap.local"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for invalid ldap_url scheme")
	}

	cfg.LDAPURL = "ldap://ldap.local"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateExpressMobileURLScheme(t *testing.T) {
	cfg := Defaults()
	cfg.DBURL = "postgres://user:pass@localhost:5432/2fa?sslmode=disable"
	cfg.JWTSecret = "secret"
	cfg.AdminJWTSecret = "admin"
	cfg.RadiusSecret = "radius"
	cfg.RedisURL = "redis://localhost:6379/0"

	cfg.ExpressMobileURL = "http://api.express-mobile.local"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for non-https express_mobile_url")
	}

	cfg.ExpressMobileURL = "https://api.express-mobile.local"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
