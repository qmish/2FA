package models

type UserStatus string

const (
	UserActive   UserStatus = "active"
	UserDisabled UserStatus = "disabled"
	UserLocked   UserStatus = "locked"
	UserPending  UserStatus = "pending"
)

type UserRole string

const (
	RoleUser  UserRole = "user"
	RoleAdmin UserRole = "admin"
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
	MethodPush     SecondFactorMethod = "push"
	MethodOTP      SecondFactorMethod = "otp"
	MethodTOTP     SecondFactorMethod = "totp"
	MethodCall     SecondFactorMethod = "call"
	MethodRecovery SecondFactorMethod = "recovery"
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
	AuditEntityChallenge    AuditEntityType = "challenge"
	AuditEntityLockout      AuditEntityType = "lockout"
	AuditEntitySession      AuditEntityType = "session"
	AuditEntityPermission   AuditEntityType = "permission"
)

type AuditAction string

const (
	AuditCreate              AuditAction = "create"
	AuditUpdate              AuditAction = "update"
	AuditDelete              AuditAction = "delete"
	AuditLogin               AuditAction = "login"
	AuditLogout              AuditAction = "logout"
	AuditRefresh             AuditAction = "refresh"
	AuditEnable              AuditAction = "enable"
	AuditDisable             AuditAction = "disable"
	AuditAuthorize           AuditAction = "authorize"
	AuditSessionRevoke       AuditAction = "session_revoke"
	AuditSessionRevokeAll    AuditAction = "session_revoke_all"
	AuditSecondFactorApprove AuditAction = "second_factor_approve"
	AuditSecondFactorDeny    AuditAction = "second_factor_deny"
	AuditLockoutCreate       AuditAction = "lockout_create"
	AuditLockoutClear        AuditAction = "lockout_clear"
)

type InviteStatus string

const (
	InvitePending InviteStatus = "pending"
	InviteUsed    InviteStatus = "used"
	InviteExpired InviteStatus = "expired"
)

type Permission string

const (
	PermissionAdminUsersRead            Permission = "admin.users.read"
	PermissionAdminUsersWrite           Permission = "admin.users.write"
	PermissionAdminGroupsRead           Permission = "admin.groups.read"
	PermissionAdminGroupsWrite          Permission = "admin.groups.write"
	PermissionAdminPoliciesRead         Permission = "admin.policies.read"
	PermissionAdminPoliciesWrite        Permission = "admin.policies.write"
	PermissionAdminRadiusClientsRead    Permission = "admin.radius_clients.read"
	PermissionAdminRadiusClientsWrite   Permission = "admin.radius_clients.write"
	PermissionAdminAuditRead            Permission = "admin.audit.read"
	PermissionAdminLoginsRead           Permission = "admin.logins.read"
	PermissionAdminRadiusRequestsRead   Permission = "admin.radius_requests.read"
	PermissionAdminRolePermissionsWrite Permission = "admin.role_permissions.write"
	PermissionAdminRolePermissionsRead  Permission = "admin.role_permissions.read"
)

type ChallengeStatus string

const (
	ChallengeCreated  ChallengeStatus = "created"
	ChallengeSent     ChallengeStatus = "sent"
	ChallengePending  ChallengeStatus = "pending"
	ChallengeApproved ChallengeStatus = "approved"
	ChallengeDenied   ChallengeStatus = "denied"
	ChallengeExpired  ChallengeStatus = "expired"
	ChallengeFailed   ChallengeStatus = "failed"
)

const (
	OTPWindowSeconds      = 90
	PushTimeoutSeconds    = 90
	CallTimeoutSeconds    = 120
	MaxAttemptsPerWindow  = 5
	AttemptsWindowSeconds = 300
	LockoutSeconds        = 900
)
