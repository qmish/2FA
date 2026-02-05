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
        {string(DeviceMobile), "mobile"},
        {string(DeviceHardware), "hardware"},
        {string(DeviceEmail), "email"},
        {string(DeviceSMS), "sms"},
        {string(DeviceActive), "active"},
        {string(DeviceDisabled), "disabled"},
        {string(MethodPush), "push"},
        {string(MethodOTP), "otp"},
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
        {string(AuditEntitySession), "session"},
        {string(AuditCreate), "create"},
        {string(AuditUpdate), "update"},
        {string(AuditDelete), "delete"},
        {string(AuditLogin), "login"},
        {string(AuditLogout), "logout"},
        {string(AuditEnable), "enable"},
        {string(AuditDisable), "disable"},
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
