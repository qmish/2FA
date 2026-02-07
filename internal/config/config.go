package config

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	HTTPPort         string        `yaml:"http_port"`
	RadiusAddr       string        `yaml:"radius_addr"`
	RadiusSecret     string        `yaml:"radius_secret"`
	DBURL            string        `yaml:"db_url"`
	RedisURL         string        `yaml:"redis_url"`
	LDAPURL          string        `yaml:"ldap_url"`
	LDAPTimeout      time.Duration `yaml:"ldap_timeout"`
	ExpressMobileURL string        `yaml:"express_mobile_url"`
	ExpressMobileKey string        `yaml:"express_mobile_key"`
	FCMServerKey     string        `yaml:"fcm_server_key"`
	JWTSecret        string        `yaml:"jwt_secret"`
	JWTIssuer        string        `yaml:"jwt_issuer"`
	JWTTTL           time.Duration `yaml:"jwt_ttl"`
	AdminJWTSecret   string        `yaml:"admin_jwt_secret"`
	AdminJWTIssuer   string        `yaml:"admin_jwt_issuer"`
	AdminJWTTTL      time.Duration `yaml:"admin_jwt_ttl"`
	AuthChallengeTTL time.Duration `yaml:"auth_challenge_ttl"`
	SessionTTL       time.Duration `yaml:"session_ttl"`
	AuthLoginLimit   int           `yaml:"auth_login_limit"`
	AuthVerifyLimit  int           `yaml:"auth_verify_limit"`
	WebAuthnRPID     string        `yaml:"webauthn_rp_id"`
	WebAuthnRPOrigin string        `yaml:"webauthn_rp_origin"`
	WebAuthnRPName   string        `yaml:"webauthn_rp_name"`
}

func Defaults() Config {
	return Config{
		HTTPPort:         "8080",
		RadiusAddr:       ":1812",
		JWTIssuer:        "2fa",
		JWTTTL:           15 * time.Minute,
		AdminJWTIssuer:   "2fa",
		AdminJWTTTL:      15 * time.Minute,
		AuthChallengeTTL: 5 * time.Minute,
		SessionTTL:       24 * time.Hour,
		AuthLoginLimit:   10,
		AuthVerifyLimit:  10,
		LDAPTimeout:      5 * time.Second,
	}
}

func LoadFromEnv() Config {
	cfg := Defaults()
	if v := os.Getenv("HTTP_PORT"); v != "" {
		cfg.HTTPPort = v
	}
	if v := os.Getenv("RADIUS_ADDR"); v != "" {
		cfg.RadiusAddr = v
	}
	if v := os.Getenv("RADIUS_SECRET"); v != "" {
		cfg.RadiusSecret = v
	}
	if v := os.Getenv("DB_URL"); v != "" {
		cfg.DBURL = v
	}
	if v := os.Getenv("REDIS_URL"); v != "" {
		cfg.RedisURL = v
	}
	if v := os.Getenv("LDAP_URL"); v != "" {
		cfg.LDAPURL = v
	}
	if v := os.Getenv("LDAP_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.LDAPTimeout = d
		}
	}
	if v := os.Getenv("EXPRESS_MOBILE_URL"); v != "" {
		cfg.ExpressMobileURL = v
	}
	if v := os.Getenv("EXPRESS_MOBILE_KEY"); v != "" {
		cfg.ExpressMobileKey = v
	}
	if v := os.Getenv("FCM_SERVER_KEY"); v != "" {
		cfg.FCMServerKey = v
	}
	if v := os.Getenv("JWT_SECRET"); v != "" {
		cfg.JWTSecret = v
	}
	if v := os.Getenv("JWT_ISSUER"); v != "" {
		cfg.JWTIssuer = v
	}
	if v := os.Getenv("JWT_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.JWTTTL = d
		}
	}
	if v := os.Getenv("ADMIN_JWT_SECRET"); v != "" {
		cfg.AdminJWTSecret = v
	}
	if v := os.Getenv("ADMIN_JWT_ISSUER"); v != "" {
		cfg.AdminJWTIssuer = v
	}
	if v := os.Getenv("ADMIN_JWT_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.AdminJWTTTL = d
		}
	}
	if v := os.Getenv("AUTH_CHALLENGE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.AuthChallengeTTL = d
		}
	}
	if v := os.Getenv("SESSION_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.SessionTTL = d
		}
	}
	if v := os.Getenv("AUTH_LOGIN_LIMIT"); v != "" {
		if limit, err := strconv.Atoi(v); err == nil {
			cfg.AuthLoginLimit = limit
		}
	}
	if v := os.Getenv("AUTH_VERIFY_LIMIT"); v != "" {
		if limit, err := strconv.Atoi(v); err == nil {
			cfg.AuthVerifyLimit = limit
		}
	}
	if v := os.Getenv("WEBAUTHN_RP_ID"); v != "" {
		cfg.WebAuthnRPID = v
	}
	if v := os.Getenv("WEBAUTHN_RP_ORIGIN"); v != "" {
		cfg.WebAuthnRPOrigin = v
	}
	if v := os.Getenv("WEBAUTHN_RP_NAME"); v != "" {
		cfg.WebAuthnRPName = v
	}
	return cfg
}

func LoadFromFile(path string) (Config, error) {
	cfg := Defaults()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func Load() (Config, error) {
	if path := os.Getenv("CONFIG_PATH"); path != "" {
		cfg, err := LoadFromFile(path)
		if err != nil {
			return cfg, err
		}
		env := LoadFromEnv()
		cfg = merge(env, cfg)
		return cfg, cfg.Validate()
	}
	cfg := LoadFromEnv()
	return cfg, cfg.Validate()
}

func merge(env Config, file Config) Config {
	if env.HTTPPort != Defaults().HTTPPort {
		file.HTTPPort = env.HTTPPort
	}
	if env.RadiusAddr != Defaults().RadiusAddr {
		file.RadiusAddr = env.RadiusAddr
	}
	if env.RadiusSecret != "" {
		file.RadiusSecret = env.RadiusSecret
	}
	if env.DBURL != "" {
		file.DBURL = env.DBURL
	}
	if env.RedisURL != "" {
		file.RedisURL = env.RedisURL
	}
	if env.LDAPURL != "" {
		file.LDAPURL = env.LDAPURL
	}
	if env.LDAPTimeout != Defaults().LDAPTimeout {
		file.LDAPTimeout = env.LDAPTimeout
	}
	if env.ExpressMobileURL != "" {
		file.ExpressMobileURL = env.ExpressMobileURL
	}
	if env.ExpressMobileKey != "" {
		file.ExpressMobileKey = env.ExpressMobileKey
	}
	if env.FCMServerKey != "" {
		file.FCMServerKey = env.FCMServerKey
	}
	if env.JWTSecret != "" {
		file.JWTSecret = env.JWTSecret
	}
	if env.JWTIssuer != Defaults().JWTIssuer {
		file.JWTIssuer = env.JWTIssuer
	}
	if env.JWTTTL != Defaults().JWTTTL {
		file.JWTTTL = env.JWTTTL
	}
	if env.AdminJWTSecret != "" {
		file.AdminJWTSecret = env.AdminJWTSecret
	}
	if env.AdminJWTIssuer != Defaults().AdminJWTIssuer {
		file.AdminJWTIssuer = env.AdminJWTIssuer
	}
	if env.AdminJWTTTL != Defaults().AdminJWTTTL {
		file.AdminJWTTTL = env.AdminJWTTTL
	}
	if env.AuthChallengeTTL != Defaults().AuthChallengeTTL {
		file.AuthChallengeTTL = env.AuthChallengeTTL
	}
	if env.SessionTTL != Defaults().SessionTTL {
		file.SessionTTL = env.SessionTTL
	}
	if env.AuthLoginLimit != Defaults().AuthLoginLimit {
		file.AuthLoginLimit = env.AuthLoginLimit
	}
	if env.AuthVerifyLimit != Defaults().AuthVerifyLimit {
		file.AuthVerifyLimit = env.AuthVerifyLimit
	}
	if env.WebAuthnRPID != "" {
		file.WebAuthnRPID = env.WebAuthnRPID
	}
	if env.WebAuthnRPOrigin != "" {
		file.WebAuthnRPOrigin = env.WebAuthnRPOrigin
	}
	if env.WebAuthnRPName != "" {
		file.WebAuthnRPName = env.WebAuthnRPName
	}
	return file
}

func (c Config) Validate() error {
	if c.DBURL == "" {
		return errors.New("db_url is required")
	}
	if !isValidURL(c.DBURL) {
		return errors.New("db_url must be a valid URL")
	}
	if !isValidPort(c.HTTPPort) {
		return errors.New("http_port must be a valid port")
	}
	if c.JWTSecret == "" {
		return errors.New("jwt_secret is required")
	}
	if strings.EqualFold(c.JWTSecret, "change_me") {
		return errors.New("jwt_secret must be set to a non-default value")
	}
	if strings.TrimSpace(c.JWTIssuer) == "" {
		return errors.New("jwt_issuer is required")
	}
	if c.AdminJWTSecret == "" {
		return errors.New("admin_jwt_secret is required")
	}
	if strings.EqualFold(c.AdminJWTSecret, "change_me") {
		return errors.New("admin_jwt_secret must be set to a non-default value")
	}
	if strings.TrimSpace(c.AdminJWTIssuer) == "" {
		return errors.New("admin_jwt_issuer is required")
	}
	if c.RadiusSecret == "" {
		return errors.New("radius_secret is required")
	}
	if strings.EqualFold(c.RadiusSecret, "change_me") {
		return errors.New("radius_secret must be set to a non-default value")
	}
	if _, _, err := net.SplitHostPort(c.RadiusAddr); err != nil {
		return errors.New("radius_addr must be in host:port format")
	}
	if c.AuthLoginLimit < 0 || c.AuthVerifyLimit < 0 {
		return errors.New("rate limit values must be non-negative")
	}
	if (c.AuthLoginLimit > 0 || c.AuthVerifyLimit > 0) && c.RedisURL == "" {
		return errors.New("redis_url is required when rate limiting is enabled")
	}
	if c.RedisURL != "" && !isValidURL(c.RedisURL) {
		return errors.New("redis_url must be a valid URL")
	}
	if c.LDAPURL != "" && !hasAllowedScheme(c.LDAPURL, "ldap", "ldaps") {
		return errors.New("ldap_url must use ldap or ldaps scheme")
	}
	if c.ExpressMobileURL != "" && !hasAllowedScheme(c.ExpressMobileURL, "https") {
		return errors.New("express_mobile_url must use https scheme")
	}
	if c.JWTTTL <= 0 || c.AdminJWTTTL <= 0 || c.AuthChallengeTTL <= 0 || c.SessionTTL <= 0 {
		return errors.New("ttl values must be positive")
	}
	if c.WebAuthnRPID != "" || c.WebAuthnRPOrigin != "" || c.WebAuthnRPName != "" {
		if c.WebAuthnRPID == "" || c.WebAuthnRPOrigin == "" || c.WebAuthnRPName == "" {
			return errors.New("webauthn_rp_id, webauthn_rp_origin, webauthn_rp_name are required together")
		}
		if !isAllowedWebAuthnOrigin(c.WebAuthnRPOrigin) {
			return errors.New("webauthn_rp_origin must use https (localhost allowed)")
		}
		if !originMatchesRPID(c.WebAuthnRPOrigin, c.WebAuthnRPID) {
			return errors.New("webauthn_rp_origin host must match webauthn_rp_id")
		}
	}
	return nil
}

func isAllowedWebAuthnOrigin(origin string) bool {
	origin = strings.TrimSpace(origin)
	if strings.HasPrefix(origin, "https://") {
		return true
	}
	if strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "http://127.0.0.1") {
		return true
	}
	return false
}

func originMatchesRPID(origin string, rpID string) bool {
	origin = strings.TrimSpace(origin)
	rpID = strings.TrimSpace(rpID)
	if origin == "" || rpID == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	rpID = strings.ToLower(rpID)
	if host == "" || rpID == "" {
		return false
	}
	if host == rpID {
		return true
	}
	return strings.HasSuffix(host, "."+rpID)
}

func isValidURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	return true
}

func isValidPort(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		return false
	}
	return port > 0 && port <= 65535
}

func hasAllowedScheme(raw string, schemes ...string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	for _, scheme := range schemes {
		if strings.EqualFold(parsed.Scheme, scheme) {
			return true
		}
	}
	return false
}
