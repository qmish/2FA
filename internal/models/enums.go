package models

type UserStatus string

const (
    UserActive   UserStatus = "active"
    UserDisabled UserStatus = "disabled"
    UserLocked   UserStatus = "locked"
    UserPending  UserStatus = "pending"
)

type DeviceType string

const (
    DeviceMobile   DeviceType = "mobile"
    DeviceHardware DeviceType = "hardware"
    DeviceEmail    DeviceType = "email"
    DeviceSMS      DeviceType = "sms"
)

type DeviceStatus string

const (
    DeviceActive   DeviceStatus = "active"
    DeviceDisabled DeviceStatus = "disabled"
)

type SecondFactorMethod string

const (
    MethodPush SecondFactorMethod = "push"
    MethodOTP  SecondFactorMethod = "otp"
    MethodCall SecondFactorMethod = "call"
)

type AuthResult string

const (
    AuthSuccess AuthResult = "success"
    AuthDeny    AuthResult = "deny"
    AuthTimeout AuthResult = "timeout"
    AuthError   AuthResult = "error"
)

type AuthChannel string

const (
    ChannelWeb    AuthChannel = "web"
    ChannelMobile AuthChannel = "mobile"
    ChannelVPN    AuthChannel = "vpn"
    ChannelMail   AuthChannel = "mail"
    ChannelRDP    AuthChannel = "rdp"
    ChannelSSH    AuthChannel = "ssh"
)

type RadiusResult string

const (
    RadiusAccept  RadiusResult = "accept"
    RadiusReject  RadiusResult = "reject"
    RadiusTimeout RadiusResult = "timeout"
    RadiusError   RadiusResult = "error"
)

type PolicyStatus string

const (
    PolicyActive   PolicyStatus = "active"
    PolicyDisabled PolicyStatus = "disabled"
)

type PolicyRuleType string

const (
    RuleGroup   PolicyRuleType = "group"
    RuleUser    PolicyRuleType = "user"
    RuleIP      PolicyRuleType = "ip"
    RuleTime    PolicyRuleType = "time"
    RuleChannel PolicyRuleType = "channel"
    RuleMethod  PolicyRuleType = "method"
)

type AuditEntityType string

const (
    AuditEntityUser         AuditEntityType = "user"
    AuditEntityDevice       AuditEntityType = "device"
    AuditEntityGroup        AuditEntityType = "group"
    AuditEntityPolicy       AuditEntityType = "policy"
    AuditEntityRadiusClient AuditEntityType = "radius_client"
    AuditEntitySession      AuditEntityType = "session"
)

type AuditAction string

const (
    AuditCreate  AuditAction = "create"
    AuditUpdate  AuditAction = "update"
    AuditDelete  AuditAction = "delete"
    AuditLogin   AuditAction = "login"
    AuditLogout  AuditAction = "logout"
    AuditEnable  AuditAction = "enable"
    AuditDisable AuditAction = "disable"
)

const (
    OTPWindowSeconds      = 90
    PushTimeoutSeconds    = 90
    CallTimeoutSeconds    = 120
    MaxAttemptsPerWindow  = 5
    AttemptsWindowSeconds = 300
    LockoutSeconds        = 900
)
