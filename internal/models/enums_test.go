package models

import "testing"

func TestEnumValues(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{string(UserActive), "active"},
		{string(UserDisabled), "disabled"},
		{string(UserLocked), "locked"},
		{string(UserPending), "pending"},
		{string(RoleUser), "user"},
		{string(RoleAdmin), "admin"},
		{string(DeviceMobile), "mobile"},
		{string(DeviceHardware), "hardware"},
		{string(DeviceEmail), "email"},
		{string(DeviceSMS), "sms"},
		{string(DeviceActive), "active"},
		{string(DeviceDisabled), "disabled"},
		{string(MethodPush), "push"},
		{string(MethodOTP), "otp"},
		{string(MethodTOTP), "totp"},
		{string(MethodCall), "call"},
		{string(AuthSuccess), "success"},
		{string(AuthDeny), "deny"},
		{string(AuthTimeout), "timeout"},
		{string(AuthError), "error"},
		{string(ChannelWeb), "web"},
		{string(ChannelMobile), "mobile"},
		{string(ChannelVPN), "vpn"},
		{string(ChannelMail), "mail"},
		{string(ChannelRDP), "rdp"},
		{string(ChannelSSH), "ssh"},
		{string(RadiusAccept), "accept"},
		{string(RadiusReject), "reject"},
		{string(RadiusTimeout), "timeout"},
		{string(RadiusError), "error"},
		{string(PolicyActive), "active"},
		{string(PolicyDisabled), "disabled"},
		{string(RuleGroup), "group"},
		{string(RuleUser), "user"},
		{string(RuleIP), "ip"},
		{string(RuleTime), "time"},
		{string(RuleChannel), "channel"},
		{string(RuleMethod), "method"},
		{string(AuditEntityUser), "user"},
		{string(AuditEntityDevice), "device"},
		{string(AuditEntityGroup), "group"},
		{string(AuditEntityPolicy), "policy"},
		{string(AuditEntityRadiusClient), "radius_client"},
		{string(AuditEntityChallenge), "challenge"},
		{string(AuditEntityLockout), "lockout"},
		{string(AuditEntitySession), "session"},
		{string(AuditEntityPermission), "permission"},
		{string(AuditCreate), "create"},
		{string(AuditUpdate), "update"},
		{string(AuditDelete), "delete"},
		{string(AuditLogin), "login"},
		{string(AuditLogout), "logout"},
		{string(AuditRefresh), "refresh"},
		{string(AuditEnable), "enable"},
		{string(AuditDisable), "disable"},
		{string(AuditAuthorize), "authorize"},
		{string(AuditSecondFactorApprove), "second_factor_approve"},
		{string(AuditSecondFactorDeny), "second_factor_deny"},
		{string(AuditLockoutCreate), "lockout_create"},
		{string(AuditLockoutClear), "lockout_clear"},
		{string(InvitePending), "pending"},
		{string(InviteUsed), "used"},
		{string(InviteExpired), "expired"},
		{string(PermissionAdminUsersRead), "admin.users.read"},
		{string(PermissionAdminUsersWrite), "admin.users.write"},
		{string(PermissionAdminGroupsRead), "admin.groups.read"},
		{string(PermissionAdminGroupsWrite), "admin.groups.write"},
		{string(PermissionAdminPoliciesRead), "admin.policies.read"},
		{string(PermissionAdminPoliciesWrite), "admin.policies.write"},
		{string(PermissionAdminRadiusClientsRead), "admin.radius_clients.read"},
		{string(PermissionAdminRadiusClientsWrite), "admin.radius_clients.write"},
		{string(PermissionAdminAuditRead), "admin.audit.read"},
		{string(PermissionAdminLoginsRead), "admin.logins.read"},
		{string(PermissionAdminRadiusRequestsRead), "admin.radius_requests.read"},
		{string(PermissionAdminRolePermissionsWrite), "admin.role_permissions.write"},
		{string(PermissionAdminRolePermissionsRead), "admin.role_permissions.read"},
		{string(ChallengeCreated), "created"},
		{string(ChallengeSent), "sent"},
		{string(ChallengePending), "pending"},
		{string(ChallengeApproved), "approved"},
		{string(ChallengeDenied), "denied"},
		{string(ChallengeExpired), "expired"},
		{string(ChallengeFailed), "failed"},
	}

	for _, tc := range cases {
		if tc.got != tc.want {
			t.Fatalf("enum value mismatch: got %q want %q", tc.got, tc.want)
		}
	}
}

func TestTimeoutConstants(t *testing.T) {
	if OTPWindowSeconds <= 0 || PushTimeoutSeconds <= 0 || CallTimeoutSeconds <= 0 {
		t.Fatalf("timeouts must be positive")
	}
	if MaxAttemptsPerWindow <= 0 || AttemptsWindowSeconds <= 0 || LockoutSeconds <= 0 {
		t.Fatalf("limits must be positive")
	}
}
