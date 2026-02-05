package config

import (
    "os"
    "time"

    "gopkg.in/yaml.v3"
)

type Config struct {
    HTTPPort         string        `yaml:"http_port"`
    RadiusAddr       string        `yaml:"radius_addr"`
    RadiusSecret     string        `yaml:"radius_secret"`
    DBURL            string        `yaml:"db_url"`
    ExpressMobileURL string        `yaml:"express_mobile_url"`
    ExpressMobileKey string        `yaml:"express_mobile_key"`
    FCMServerKey     string        `yaml:"fcm_server_key"`
    AdminJWTSecret   string        `yaml:"admin_jwt_secret"`
    AdminJWTIssuer   string        `yaml:"admin_jwt_issuer"`
    AdminJWTTTL      time.Duration `yaml:"admin_jwt_ttl"`
}

func Defaults() Config {
    return Config{
        HTTPPort:       "8080",
        RadiusAddr:     ":1812",
        AdminJWTIssuer: "2fa",
        AdminJWTTTL:    15 * time.Minute,
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
    if v := os.Getenv("EXPRESS_MOBILE_URL"); v != "" {
        cfg.ExpressMobileURL = v
    }
    if v := os.Getenv("EXPRESS_MOBILE_KEY"); v != "" {
        cfg.ExpressMobileKey = v
    }
    if v := os.Getenv("FCM_SERVER_KEY"); v != "" {
        cfg.FCMServerKey = v
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
        return cfg, nil
    }
    return LoadFromEnv(), nil
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
    if env.ExpressMobileURL != "" {
        file.ExpressMobileURL = env.ExpressMobileURL
    }
    if env.ExpressMobileKey != "" {
        file.ExpressMobileKey = env.ExpressMobileKey
    }
    if env.FCMServerKey != "" {
        file.FCMServerKey = env.FCMServerKey
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
    return file
}
