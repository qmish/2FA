package models

import "time"

type User struct {
    ID           string
    Username     string
    Email        string
    Phone        string
    Status       UserStatus
    Role         UserRole
    PasswordHash string
    AdDN         string
    CreatedAt    time.Time
    UpdatedAt    time.Time
}

type Device struct {
    ID         string
    UserID     string
    Type       DeviceType
    Name       string
    Status     DeviceStatus
    LastSeenAt *time.Time
    CreatedAt  time.Time
}

type UserSession struct {
    ID               string
    UserID           string
    RefreshTokenHash string
    IP               string
    UserAgent        string
    ExpiresAt        time.Time
    CreatedAt        time.Time
    LastSeenAt       *time.Time
    RevokedAt        *time.Time
}

type Challenge struct {
    ID         string
    UserID     string
    Method     SecondFactorMethod
    Status     ChallengeStatus
    CodeHash   string
    ProviderID string
    ExpiresAt  time.Time
    CreatedAt  time.Time
    UpdatedAt  time.Time
}

type Policy struct {
    ID        string
    Name      string
    Priority  int
    Status    PolicyStatus
    CreatedAt time.Time
}

type PolicyRule struct {
    ID        string
    PolicyID  string
    RuleType  PolicyRuleType
    RuleValue string
    CreatedAt time.Time
}

type RadiusClient struct {
    ID        string
    Name      string
    IP        string
    Secret    string
    Enabled   bool
    CreatedAt time.Time
}

type AuditEvent struct {
    ID          string
    ActorUserID string
    Action      AuditAction
    EntityType  AuditEntityType
    EntityID    string
    Payload     string
    IP          string
    CreatedAt   time.Time
}

type LoginHistory struct {
    ID        string
    UserID    string
    Channel   AuthChannel
    Result    AuthResult
    IP        string
    DeviceID  string
    CreatedAt time.Time
}

type Lockout struct {
    ID        string
    UserID    string
    IP        string
    Reason    string
    ExpiresAt time.Time
    CreatedAt time.Time
}

type RadiusRequest struct {
    ID            string
    ClientID      string
    Username      string
    NASIP         string
    Result        RadiusResult
    RequestID     string
    RequestAttrs  string
    ResponseAttrs string
    CreatedAt     time.Time
}

type Group struct {
    ID          string
    Name        string
    Description string
    CreatedAt   time.Time
}
