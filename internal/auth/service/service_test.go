package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/qmish/2FA/internal/auth/jwt"
	"github.com/qmish/2FA/internal/auth/providers"
	"github.com/qmish/2FA/internal/dto"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/internal/repository"
)

func TestAuthLoginVerify(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash), Phone: "+79990000000"}}
	challenges := &fakeChallengeRepo{}
	sessions := &fakeSessionRepo{}

	jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
	svc := NewService(users, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	svc.codeGen = func() string { return "123456" }

	loginResp, err := svc.Login(context.Background(), dto.LoginRequest{Username: "alice", Password: "pass"})
	if err != nil {
		t.Fatalf("login error: %v", err)
	}
	if loginResp.ChallengeID == "" {
		t.Fatalf("missing challenge id")
	}
	if loginResp.Status != models.ChallengeCreated {
		t.Fatalf("unexpected challenge status: %v", loginResp.Status)
	}

	verifyResp, err := svc.VerifySecondFactor(context.Background(), dto.VerifyRequest{
		UserID:      "u1",
		ChallengeID: loginResp.ChallengeID,
		Method:      models.MethodOTP,
		Code:        "123456",
	})
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if verifyResp.AccessToken == "" || verifyResp.RefreshToken == "" {
		t.Fatalf("missing tokens")
	}

	refreshed, err := svc.Refresh(context.Background(), dto.RefreshRequest{RefreshToken: verifyResp.RefreshToken}, "127.0.0.1")
	if err != nil || refreshed.AccessToken == "" {
		t.Fatalf("refresh error: %v", err)
	}
}

func TestAuthLoginProviderSuccess(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash), Phone: "+79990000000"}}
	challenges := &fakeChallengeRepo{}
	sessions := &fakeSessionRepo{}
	registry := providers.NewRegistry()
	registry.RegisterSMS(providers.DefaultSMSProvider, fakeSMSProvider{providerID: "prov-1"})

	jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
	svc := NewService(users, challenges, sessions, registry, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	svc.codeGen = func() string { return "123456" }

	loginResp, err := svc.Login(context.Background(), dto.LoginRequest{Username: "alice", Password: "pass"})
	if err != nil {
		t.Fatalf("login error: %v", err)
	}
	item, ok := challenges.items[loginResp.ChallengeID]
	if !ok {
		t.Fatalf("missing challenge in repo")
	}
	if item.Status != models.ChallengeSent || item.ProviderID != "prov-1" {
		t.Fatalf("unexpected challenge state: %+v", item)
	}
}

func TestAuthLoginProviderFailure(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash), Phone: "+79990000000"}}
	challenges := &fakeChallengeRepo{}
	sessions := &fakeSessionRepo{}
	registry := providers.NewRegistry()
	registry.RegisterSMS(providers.DefaultSMSProvider, fakeSMSProvider{err: errors.New("fail")})

	jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
	svc := NewService(users, challenges, sessions, registry, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	svc.codeGen = func() string { return "123456" }

	_, err := svc.Login(context.Background(), dto.LoginRequest{Username: "alice", Password: "pass"})
	if !errors.Is(err, ErrSecondFactorFailed) {
		t.Fatalf("expected ErrSecondFactorFailed, got %v", err)
	}
	for _, item := range challenges.items {
		if item.Status != models.ChallengeFailed {
			t.Fatalf("unexpected challenge status: %v", item.Status)
		}
	}
}

func TestAuthVerifyMethodMismatch(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash), Phone: "+79990000000"}}
	challenges := &fakeChallengeRepo{}
	sessions := &fakeSessionRepo{}

	jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
	svc := NewService(users, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	svc.codeGen = func() string { return "123456" }

	loginResp, err := svc.Login(context.Background(), dto.LoginRequest{Username: "alice", Password: "pass", Method: models.MethodOTP})
	if err != nil {
		t.Fatalf("login error: %v", err)
	}
	_, err = svc.VerifySecondFactor(context.Background(), dto.VerifyRequest{
		UserID:      "u1",
		ChallengeID: loginResp.ChallengeID,
		Method:      models.MethodCall,
		Code:        "123456",
	})
	if !errors.Is(err, ErrSecondFactorFailed) {
		t.Fatalf("expected ErrSecondFactorFailed, got %v", err)
	}
}

func TestAuthVerifySecondFactorRecordsDevice(t *testing.T) {
	challenges := &fakeChallengeRepo{items: map[string]challengeItem{}}
	sessions := &fakeSessionRepo{}
	devices := &fakeDeviceRepo{}
	svc := NewService(fakeUserRepo{}, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)
	svc.WithDevices(devices)

	challenge := &models.Challenge{
		ID:        "c1",
		UserID:    "u1",
		Method:    models.MethodOTP,
		Status:    models.ChallengeCreated,
		CodeHash:  hash("123456"),
		ExpiresAt: time.Now().Add(time.Minute),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := challenges.Create(context.Background(), challenge); err != nil {
		t.Fatalf("create challenge error: %v", err)
	}
	_, err := svc.VerifySecondFactor(context.Background(), dto.VerifyRequest{
		UserID:      "u1",
		ChallengeID: "c1",
		Method:      models.MethodOTP,
		Code:        "123456",
		UserAgent:   "Mozilla/5.0",
	})
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if devices.upserted == nil {
		t.Fatalf("expected device to be recorded")
	}
	if devices.upserted.UserID != "u1" || devices.upserted.Type != models.DeviceWeb || devices.upserted.Name != "Mozilla/5.0" {
		t.Fatalf("unexpected device: %+v", devices.upserted)
	}
	if devices.upserted.Status != models.DeviceActive || devices.upserted.LastSeenAt == nil {
		t.Fatalf("unexpected device status: %+v", devices.upserted)
	}
}

func TestAuthVerifySecondFactorPushCodeMismatch(t *testing.T) {
	challenges := &fakeChallengeRepo{items: map[string]challengeItem{}}
	sessions := &fakeSessionRepo{}
	svc := NewService(fakeUserRepo{}, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

	challenge := &models.Challenge{
		ID:        "c1",
		UserID:    "u1",
		Method:    models.MethodPush,
		Status:    models.ChallengeCreated,
		CodeHash:  hash("123456"),
		ExpiresAt: time.Now().Add(time.Minute),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := challenges.Create(context.Background(), challenge); err != nil {
		t.Fatalf("create challenge error: %v", err)
	}
	_, err := svc.VerifySecondFactor(context.Background(), dto.VerifyRequest{
		UserID:      "u1",
		ChallengeID: "c1",
		Method:      models.MethodPush,
		Code:        "000000",
	})
	if !errors.Is(err, ErrSecondFactorFailed) {
		t.Fatalf("expected ErrSecondFactorFailed, got %v", err)
	}
}

func TestAuthVerifySecondFactorCallCodeOK(t *testing.T) {
	challenges := &fakeChallengeRepo{items: map[string]challengeItem{}}
	sessions := &fakeSessionRepo{}
	svc := NewService(fakeUserRepo{}, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

	challenge := &models.Challenge{
		ID:        "c1",
		UserID:    "u1",
		Method:    models.MethodCall,
		Status:    models.ChallengeCreated,
		CodeHash:  hash("654321"),
		ExpiresAt: time.Now().Add(time.Minute),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := challenges.Create(context.Background(), challenge); err != nil {
		t.Fatalf("create challenge error: %v", err)
	}
	resp, err := svc.VerifySecondFactor(context.Background(), dto.VerifyRequest{
		UserID:      "u1",
		ChallengeID: "c1",
		Method:      models.MethodCall,
		Code:        "654321",
	})
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Fatalf("missing tokens")
	}
}

func TestAuthLoginLocked(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash)}}
	lockouts := &fakeLockoutRepo{active: &models.Lockout{ID: "l1"}}
	svc := NewService(users, &fakeChallengeRepo{}, &fakeSessionRepo{}, nil, lockouts, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

	_, err := svc.Login(context.Background(), dto.LoginRequest{Username: "alice", Password: "pass", IP: "127.0.0.1"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
}

func TestAuthLoginCreatesLockout(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash)}}
	lockouts := &fakeLockoutRepo{}
	logins := &fakeLoginHistoryRepo{failures: models.MaxAttemptsPerWindow}
	audits := &recordAuditRepo{}
	svc := NewService(users, &fakeChallengeRepo{}, &fakeSessionRepo{}, nil, lockouts, logins, audits, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

	_, err := svc.Login(context.Background(), dto.LoginRequest{Username: "alice", Password: "bad", IP: "127.0.0.1"})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if lockouts.created == nil {
		t.Fatalf("expected lockout to be created")
	}
	if audits.count != 2 || audits.last.Action != models.AuditLockoutCreate || audits.last.EntityType != models.AuditEntityLockout || audits.last.EntityID != lockouts.created.ID || audits.last.Payload != "too_many_attempts" {
		t.Fatalf("unexpected audit event: %+v", audits.last)
	}
}

func TestAuthLoginPolicyDenied(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	user := &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash)}
	users := fakeUserRepo{user: user}
	challenges := &fakeChallengeRepo{}
	sessions := &fakeSessionRepo{}
	jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
	svc := NewService(users, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	svc.WithPolicies(
		fakePolicyRepo{policies: map[string]models.Policy{
			"p1": {ID: "p1", Name: "deny", Priority: 0, Status: models.PolicyActive},
		}},
		fakePolicyRuleRepo{rules: map[string][]models.PolicyRule{
			"p1": {
				{ID: "r1", PolicyID: "p1", RuleType: models.RuleChannel, RuleValue: "vpn"},
			},
		}},
		fakeUserGroupRepo{groups: []models.Group{{ID: "g1", Name: "ops"}}},
		fakeGroupPolicyRepo{policies: map[string]string{"g1": "p1"}},
	)

	_, err := svc.Login(context.Background(), dto.LoginRequest{
		Username: "alice",
		Password: "pass",
		Channel:  models.ChannelWeb,
		IP:       "127.0.0.1",
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
}

func TestAuthLoginPolicyAllowed(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	user := &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash)}
	users := fakeUserRepo{user: user}
	challenges := &fakeChallengeRepo{}
	sessions := &fakeSessionRepo{}
	jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
	svc := NewService(users, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	svc.WithPolicies(
		fakePolicyRepo{policies: map[string]models.Policy{
			"p1": {ID: "p1", Name: "allow", Priority: 0, Status: models.PolicyActive},
		}},
		fakePolicyRuleRepo{rules: map[string][]models.PolicyRule{
			"p1": {
				{ID: "r1", PolicyID: "p1", RuleType: models.RuleChannel, RuleValue: "web"},
				{ID: "r2", PolicyID: "p1", RuleType: models.RuleMethod, RuleValue: "otp"},
			},
		}},
		fakeUserGroupRepo{groups: []models.Group{{ID: "g1", Name: "ops"}}},
		fakeGroupPolicyRepo{policies: map[string]string{"g1": "p1"}},
	)

	resp, err := svc.Login(context.Background(), dto.LoginRequest{
		Username: "alice",
		Password: "pass",
		Channel:  models.ChannelWeb,
		IP:       "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ChallengeID == "" {
		t.Fatalf("expected challenge id")
	}
}

func TestAuthVerifySecondFactorTOTP(t *testing.T) {
	now := time.Date(2026, 2, 6, 10, 0, 0, 0, time.UTC)
	secret := "JBSWY3DPEHPK3PXP"
	code, err := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("generate code error: %v", err)
	}
	challenges := &fakeChallengeRepo{items: map[string]challengeItem{}}
	sessions := &fakeSessionRepo{}
	otpRepo := &fakeOTPSecretRepo{secret: &models.OTPSecret{
		ID:        "s1",
		UserID:    "u1",
		Secret:    secret,
		Issuer:    "2FA",
		Digits:    6,
		Period:    30,
		Enabled:   true,
		CreatedAt: now.Add(-time.Hour),
	}}
	jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
	svc := NewService(fakeUserRepo{}, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	svc.WithOTPSecrets(otpRepo)
	svc.now = func() time.Time { return now }

	challenge := &models.Challenge{
		ID:        "c1",
		UserID:    "u1",
		Method:    models.MethodTOTP,
		Status:    models.ChallengeCreated,
		ExpiresAt: now.Add(time.Minute),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := challenges.Create(context.Background(), challenge); err != nil {
		t.Fatalf("create challenge error: %v", err)
	}
	resp, err := svc.VerifySecondFactor(context.Background(), dto.VerifyRequest{
		UserID:      "u1",
		ChallengeID: "c1",
		Method:      models.MethodTOTP,
		Code:        code,
		IP:          "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Fatalf("missing tokens")
	}
}

func TestAuthGenerateRecoveryCodes(t *testing.T) {
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive}}
	recovery := &fakeRecoveryCodeRepo{}
	svc := NewService(users, &fakeChallengeRepo{}, &fakeSessionRepo{}, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)
	svc.WithRecoveryCodes(recovery)

	resp, err := svc.GenerateRecoveryCodes(context.Background(), "u1")
	if err != nil {
		t.Fatalf("generate recovery codes error: %v", err)
	}
	if len(resp.Codes) == 0 {
		t.Fatalf("expected recovery codes")
	}
	unique := map[string]struct{}{}
	for _, code := range resp.Codes {
		if code == "" {
			t.Fatalf("empty recovery code")
		}
		unique[code] = struct{}{}
	}
	if len(unique) != len(resp.Codes) {
		t.Fatalf("duplicate recovery codes")
	}
	if recovery.createdCount != len(resp.Codes) {
		t.Fatalf("expected %d codes created, got %d", len(resp.Codes), recovery.createdCount)
	}
}

func TestAuthVerifySecondFactorRecovery(t *testing.T) {
	challenges := &fakeChallengeRepo{items: map[string]challengeItem{}}
	sessions := &fakeSessionRepo{}
	recovery := &fakeRecoveryCodeRepo{
		codes: map[string]bool{
			hash("rc-1"): false,
		},
	}
	svc := NewService(fakeUserRepo{}, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)
	svc.WithRecoveryCodes(recovery)

	challenge := &models.Challenge{
		ID:        "c1",
		UserID:    "u1",
		Method:    models.MethodRecovery,
		Status:    models.ChallengeCreated,
		ExpiresAt: time.Now().Add(time.Minute),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := challenges.Create(context.Background(), challenge); err != nil {
		t.Fatalf("create challenge error: %v", err)
	}
	if _, err := svc.VerifySecondFactor(context.Background(), dto.VerifyRequest{
		UserID:      "u1",
		ChallengeID: "c1",
		Method:      models.MethodRecovery,
		Code:        "rc-1",
		IP:          "127.0.0.1",
	}); err != nil {
		t.Fatalf("verify recovery error: %v", err)
	}
	if !recovery.consumed {
		t.Fatalf("expected recovery code to be consumed")
	}
}

func TestAuthVerifySecondFactorTOTPInvalid(t *testing.T) {
	now := time.Date(2026, 2, 6, 10, 0, 0, 0, time.UTC)
	challenges := &fakeChallengeRepo{items: map[string]challengeItem{}}
	sessions := &fakeSessionRepo{}
	otpRepo := &fakeOTPSecretRepo{secret: &models.OTPSecret{
		ID:        "s1",
		UserID:    "u1",
		Secret:    "JBSWY3DPEHPK3PXP",
		Issuer:    "2FA",
		Digits:    6,
		Period:    30,
		Enabled:   true,
		CreatedAt: now.Add(-time.Hour),
	}}
	jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
	svc := NewService(fakeUserRepo{}, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	svc.WithOTPSecrets(otpRepo)
	svc.now = func() time.Time { return now }

	challenge := &models.Challenge{
		ID:        "c1",
		UserID:    "u1",
		Method:    models.MethodTOTP,
		Status:    models.ChallengeCreated,
		ExpiresAt: now.Add(time.Minute),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := challenges.Create(context.Background(), challenge); err != nil {
		t.Fatalf("create challenge error: %v", err)
	}
	_, err := svc.VerifySecondFactor(context.Background(), dto.VerifyRequest{
		UserID:      "u1",
		ChallengeID: "c1",
		Method:      models.MethodTOTP,
		Code:        "000000",
		IP:          "127.0.0.1",
	})
	if !errors.Is(err, ErrSecondFactorFailed) {
		t.Fatalf("expected ErrSecondFactorFailed, got %v", err)
	}
}

func TestAuthSetupTOTP(t *testing.T) {
	user := &models.User{ID: "u1", Username: "alice", Status: models.UserActive}
	users := fakeUserRepo{user: user}
	repo := &fakeOTPSecretRepo{}
	jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
	svc := NewService(users, &fakeChallengeRepo{}, &fakeSessionRepo{}, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	svc.WithOTPSecrets(repo)
	svc.WithTOTPConfig("2FA", 6, 30)

	resp, err := svc.SetupTOTP(context.Background(), "u1")
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}
	if resp.Secret == "" || resp.OTPAuthURL == "" {
		t.Fatalf("missing setup data: %+v", resp)
	}
	if repo.created == nil || repo.created.UserID != "u1" || !repo.created.Enabled {
		t.Fatalf("secret not created: %+v", repo.created)
	}
}

func TestAuthDisableTOTP(t *testing.T) {
	repo := &fakeOTPSecretRepo{secret: &models.OTPSecret{ID: "s1", UserID: "u1", Enabled: true}}
	jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
	svc := NewService(fakeUserRepo{}, &fakeChallengeRepo{}, &fakeSessionRepo{}, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	svc.WithOTPSecrets(repo)

	if err := svc.DisableTOTP(context.Background(), "u1"); err != nil {
		t.Fatalf("disable error: %v", err)
	}
	if repo.disabledID != "s1" {
		t.Fatalf("expected disable s1, got %s", repo.disabledID)
	}
}

func TestAuthLoginLDAPSuccess(t *testing.T) {
	user := &models.User{
		ID:       "u1",
		Username: "alice",
		Status:   models.UserActive,
		AdDN:     "cn=alice,dc=example,dc=com",
	}
	users := fakeUserRepo{user: user}
	challenges := &fakeChallengeRepo{}
	sessions := &fakeSessionRepo{}
	jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
	svc := NewService(users, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	svc.WithLDAPAuth(fakeLDAPAuth{})

	resp, err := svc.Login(context.Background(), dto.LoginRequest{
		Username: "alice",
		Password: "pass",
		IP:       "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ChallengeID == "" {
		t.Fatalf("expected challenge id")
	}
}

func TestAuthLoginLDAPFailure(t *testing.T) {
	user := &models.User{
		ID:       "u1",
		Username: "alice",
		Status:   models.UserActive,
		AdDN:     "cn=alice,dc=example,dc=com",
	}
	users := fakeUserRepo{user: user}
	challenges := &fakeChallengeRepo{}
	sessions := &fakeSessionRepo{}
	jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
	svc := NewService(users, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	svc.WithLDAPAuth(fakeLDAPAuth{err: errors.New("bad creds")})

	_, err := svc.Login(context.Background(), dto.LoginRequest{
		Username: "alice",
		Password: "bad",
		IP:       "127.0.0.1",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthRegisterSuccess(t *testing.T) {
	invites := &fakeInviteRepo{
		items: map[string]*models.Invite{},
	}
	token := "invite-token"
	now := time.Now()
	invite := &models.Invite{
		ID:        "i1",
		TokenHash: hash(token),
		Email:     "a@example.com",
		Role:      models.RoleUser,
		Status:    models.InvitePending,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}
	invites.items[invite.TokenHash] = invite
	repo := &recordUserRepo{}
	svc := NewService(repo, &fakeChallengeRepo{}, &fakeSessionRepo{}, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)
	svc.WithInvites(invites)
	svc.now = func() time.Time { return now }

	resp, err := svc.Register(context.Background(), dto.RegisterRequest{
		Token:    token,
		Username: "alice",
		Password: "pass",
	})
	if err != nil {
		t.Fatalf("register error: %v", err)
	}
	if resp.UserID == "" || repo.created == nil || repo.created.Username != "alice" || repo.created.Email != "a@example.com" {
		t.Fatalf("unexpected user: %+v resp=%+v", repo.created, resp)
	}
	if invites.usedID != "i1" || invites.usedBy != repo.created.ID {
		t.Fatalf("invite not marked used: %+v", invites)
	}
}

func TestAuthRegisterInvalidInvite(t *testing.T) {
	invites := &fakeInviteRepo{
		items: map[string]*models.Invite{},
	}
	svc := NewService(fakeUserRepo{}, &fakeChallengeRepo{}, &fakeSessionRepo{}, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)
	svc.WithInvites(invites)

	_, err := svc.Register(context.Background(), dto.RegisterRequest{
		Token:    "missing",
		Username: "alice",
		Password: "pass",
	})
	if !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("expected ErrInviteInvalid, got %v", err)
	}
}

func TestAuthRegisterExpiredInvite(t *testing.T) {
	invites := &fakeInviteRepo{
		items: map[string]*models.Invite{},
	}
	token := "expired-token"
	now := time.Now()
	invite := &models.Invite{
		ID:        "i1",
		TokenHash: hash(token),
		Role:      models.RoleUser,
		Status:    models.InvitePending,
		ExpiresAt: now.Add(-time.Minute),
		CreatedAt: now.Add(-time.Hour),
	}
	invites.items[invite.TokenHash] = invite
	svc := NewService(fakeUserRepo{}, &fakeChallengeRepo{}, &fakeSessionRepo{}, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)
	svc.WithInvites(invites)
	svc.now = func() time.Time { return now }

	_, err := svc.Register(context.Background(), dto.RegisterRequest{
		Token:    token,
		Username: "alice",
		Password: "pass",
	})
	if !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("expected ErrInviteInvalid, got %v", err)
	}
	if invites.expiredCount == 0 {
		t.Fatalf("expected invite expiration update")
	}
}

func TestAuthLogoutOK(t *testing.T) {
	sessions := &fakeSessionRepo{
		items: map[string]models.UserSession{
			"refresh": {ID: "s1", UserID: "u1"},
		},
	}
	svc := NewService(fakeUserRepo{}, &fakeChallengeRepo{}, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

	if err := svc.Logout(context.Background(), "u1", "s1", "127.0.0.1"); err != nil {
		t.Fatalf("logout error: %v", err)
	}
	if sessions.revokedID != "s1" {
		t.Fatalf("expected revoke s1, got %s", sessions.revokedID)
	}
}

func TestAuthLogoutForbidden(t *testing.T) {
	sessions := &fakeSessionRepo{
		items: map[string]models.UserSession{
			"refresh": {ID: "s1", UserID: "u2"},
		},
	}
	svc := NewService(fakeUserRepo{}, &fakeChallengeRepo{}, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

	if err := svc.Logout(context.Background(), "u1", "s1", "127.0.0.1"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
}

func TestAuthLogoutAudits(t *testing.T) {
	sessions := &fakeSessionRepo{
		items: map[string]models.UserSession{
			"refresh": {ID: "s1", UserID: "u1"},
		},
	}
	audits := &recordAuditRepo{}
	svc := NewService(fakeUserRepo{}, &fakeChallengeRepo{}, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, audits, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

	if err := svc.Logout(context.Background(), "u1", "s1", "127.0.0.1"); err != nil {
		t.Fatalf("logout error: %v", err)
	}
	if audits.count != 1 || audits.last.Action != models.AuditLogout || audits.last.EntityType != models.AuditEntitySession || audits.last.EntityID != "s1" || audits.last.ActorUserID != "u1" || audits.last.IP != "127.0.0.1" {
		t.Fatalf("unexpected audit event: %+v", audits.last)
	}
}

func TestAuthRefreshAudits(t *testing.T) {
	refresh := "token1"
	refreshHash := hash(refresh)
	sessions := &fakeSessionRepo{
		items: map[string]models.UserSession{
			refreshHash: {ID: "s1", UserID: "u1", RefreshTokenHash: refreshHash, ExpiresAt: time.Now().Add(time.Hour)},
		},
	}
	audits := &recordAuditRepo{}
	svc := NewService(fakeUserRepo{}, &fakeChallengeRepo{}, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, audits, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

	if _, err := svc.Refresh(context.Background(), dto.RefreshRequest{RefreshToken: refresh}, "127.0.0.1"); err != nil {
		t.Fatalf("refresh error: %v", err)
	}
	if audits.count != 1 || audits.last.Action != models.AuditRefresh || audits.last.EntityType != models.AuditEntitySession || audits.last.EntityID != "s1" || audits.last.ActorUserID != "u1" || audits.last.IP != "127.0.0.1" {
		t.Fatalf("unexpected audit event: %+v", audits.last)
	}
}

func TestAuthVerifySecondFactorAuditApprove(t *testing.T) {
	challenges := &fakeChallengeRepo{
		items: map[string]challengeItem{},
	}
	sessions := &fakeSessionRepo{}
	audits := &recordAuditRepo{}
	svc := NewService(fakeUserRepo{}, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, audits, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

	challenge := &models.Challenge{
		ID:        "c1",
		UserID:    "u1",
		Method:    models.MethodOTP,
		Status:    models.ChallengeCreated,
		CodeHash:  hash("123456"),
		ExpiresAt: time.Now().Add(time.Minute),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := challenges.Create(context.Background(), challenge); err != nil {
		t.Fatalf("create challenge error: %v", err)
	}
	if _, err := svc.VerifySecondFactor(context.Background(), dto.VerifyRequest{
		UserID:      "u1",
		ChallengeID: "c1",
		Method:      models.MethodOTP,
		Code:        "123456",
		IP:          "127.0.0.1",
	}); err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if audits.count != 1 || audits.last.Action != models.AuditSecondFactorApprove || audits.last.EntityType != models.AuditEntityChallenge || audits.last.EntityID != "c1" || audits.last.ActorUserID != "u1" || audits.last.IP != "127.0.0.1" || audits.last.Payload != "otp" {
		t.Fatalf("unexpected audit event: %+v", audits.last)
	}
}

func TestAuthVerifySecondFactorAuditDeny(t *testing.T) {
	challenges := &fakeChallengeRepo{
		items: map[string]challengeItem{},
	}
	sessions := &fakeSessionRepo{}
	audits := &recordAuditRepo{}
	svc := NewService(fakeUserRepo{}, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, audits, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

	challenge := &models.Challenge{
		ID:        "c1",
		UserID:    "u1",
		Method:    models.MethodOTP,
		Status:    models.ChallengeCreated,
		CodeHash:  hash("123456"),
		ExpiresAt: time.Now().Add(time.Minute),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := challenges.Create(context.Background(), challenge); err != nil {
		t.Fatalf("create challenge error: %v", err)
	}
	if _, err := svc.VerifySecondFactor(context.Background(), dto.VerifyRequest{
		UserID:      "u1",
		ChallengeID: "c1",
		Method:      models.MethodOTP,
		Code:        "000000",
		IP:          "127.0.0.1",
	}); !errors.Is(err, ErrSecondFactorFailed) {
		t.Fatalf("expected ErrSecondFactorFailed, got %v", err)
	}
	if audits.count != 2 || audits.last.Action != models.AuditSecondFactorDeny || audits.last.EntityType != models.AuditEntityChallenge || audits.last.EntityID != "c1" || audits.last.ActorUserID != "u1" || audits.last.IP != "127.0.0.1" || audits.last.Payload != "otp" {
		t.Fatalf("unexpected audit event: %+v", audits.last)
	}
}

type fakeUserRepo struct {
	user *models.User
}

func (f fakeUserRepo) GetByID(ctx context.Context, id string) (*models.User, error) {
	if f.user != nil && f.user.ID == id {
		return f.user, nil
	}
	return nil, repository.ErrNotFound
}
func (f fakeUserRepo) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	if f.user != nil && f.user.Username == username {
		return f.user, nil
	}
	return nil, repository.ErrNotFound
}
func (f fakeUserRepo) GetByUsernameAndRole(ctx context.Context, username string, role models.UserRole) (*models.User, error) {
	return nil, repository.ErrNotFound
}
func (f fakeUserRepo) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	return nil, repository.ErrNotFound
}
func (f fakeUserRepo) GetByPhone(ctx context.Context, phone string) (*models.User, error) {
	return nil, repository.ErrNotFound
}
func (f fakeUserRepo) List(ctx context.Context, filter repository.UserListFilter, limit, offset int) ([]models.User, int, error) {
	return nil, 0, nil
}
func (f fakeUserRepo) Create(ctx context.Context, u *models.User) error { return nil }
func (f fakeUserRepo) Update(ctx context.Context, u *models.User) error { return nil }
func (f fakeUserRepo) Delete(ctx context.Context, id string) error      { return nil }
func (f fakeUserRepo) SetStatus(ctx context.Context, id string, status models.UserStatus) error {
	return nil
}

type fakeChallengeRepo struct {
	items map[string]challengeItem
}

type challengeItem struct {
	models.Challenge
	plainCode string
}

func (f *fakeChallengeRepo) GetByID(ctx context.Context, id string) (*models.Challenge, error) {
	if f.items == nil {
		return nil, repository.ErrNotFound
	}
	item, ok := f.items[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return &item.Challenge, nil
}
func (f *fakeChallengeRepo) GetActiveByUserAndMethod(ctx context.Context, userID string, method models.SecondFactorMethod) (*models.Challenge, error) {
	for _, item := range f.items {
		if item.UserID == userID && item.Method == method && (item.Status == models.ChallengeCreated || item.Status == models.ChallengeSent || item.Status == models.ChallengePending) {
			c := item.Challenge
			return &c, nil
		}
	}
	return nil, repository.ErrNotFound
}
func (f *fakeChallengeRepo) Create(ctx context.Context, c *models.Challenge) error {
	if f.items == nil {
		f.items = map[string]challengeItem{}
	}
	f.items[c.ID] = challengeItem{Challenge: *c, plainCode: ""} // plainCode set below
	return nil
}
func (f *fakeChallengeRepo) UpdateStatus(ctx context.Context, id string, status models.ChallengeStatus) error {
	item := f.items[id]
	item.Status = status
	f.items[id] = item
	return nil
}
func (f *fakeChallengeRepo) UpdateDelivery(ctx context.Context, id string, providerID string, status models.ChallengeStatus) error {
	item := f.items[id]
	item.Status = status
	item.ProviderID = providerID
	f.items[id] = item
	return nil
}
func (f *fakeChallengeRepo) MarkExpired(ctx context.Context, now time.Time) (int64, error) {
	return 0, nil
}

type fakeSessionRepo struct {
	items     map[string]models.UserSession
	revokedID string
}

type fakeLockoutRepo struct {
	active  *models.Lockout
	created *models.Lockout
}

func (f *fakeLockoutRepo) Create(ctx context.Context, l *models.Lockout) error {
	f.created = l
	return nil
}
func (f *fakeLockoutRepo) GetActive(ctx context.Context, userID string, ip string, now time.Time) (*models.Lockout, error) {
	if f.active != nil {
		return f.active, nil
	}
	return nil, repository.ErrNotFound
}
func (f *fakeLockoutRepo) ClearExpired(ctx context.Context, now time.Time) (int64, error) {
	return 0, nil
}
func (f *fakeLockoutRepo) List(ctx context.Context, filter repository.LockoutFilter, limit, offset int) ([]models.Lockout, int, error) {
	return nil, 0, nil
}
func (f *fakeLockoutRepo) ClearByFilter(ctx context.Context, filter repository.LockoutFilter) error {
	return nil
}

type fakeLoginHistoryRepo struct {
	failures int
}

func (f *fakeLoginHistoryRepo) Create(ctx context.Context, h *models.LoginHistory) error { return nil }
func (f *fakeLoginHistoryRepo) List(ctx context.Context, filter repository.LoginHistoryFilter, limit, offset int) ([]models.LoginHistory, int, error) {
	return nil, 0, nil
}
func (f *fakeLoginHistoryRepo) CountFailures(ctx context.Context, userID string, since time.Time) (int, error) {
	return f.failures, nil
}

type fakeAuditRepo struct{}

func (f *fakeAuditRepo) Create(ctx context.Context, e *models.AuditEvent) error { return nil }
func (f *fakeAuditRepo) List(ctx context.Context, filter repository.AuditFilter, limit, offset int) ([]models.AuditEvent, int, error) {
	return nil, 0, nil
}

type recordAuditRepo struct {
	count int
	last  *models.AuditEvent
}

func (r *recordAuditRepo) Create(ctx context.Context, e *models.AuditEvent) error {
	r.count++
	r.last = e
	return nil
}
func (r *recordAuditRepo) List(ctx context.Context, filter repository.AuditFilter, limit, offset int) ([]models.AuditEvent, int, error) {
	return nil, 0, nil
}

type fakeSMSProvider struct {
	providerID string
	err        error
}

func (f fakeSMSProvider) SendSMS(ctx context.Context, to, message string) (string, error) {
	return f.providerID, f.err
}

type fakePolicyRepo struct {
	policies map[string]models.Policy
}

func (f fakePolicyRepo) GetByID(ctx context.Context, id string) (*models.Policy, error) {
	if p, ok := f.policies[id]; ok {
		cp := p
		return &cp, nil
	}
	return nil, repository.ErrNotFound
}
func (f fakePolicyRepo) GetByName(ctx context.Context, name string) (*models.Policy, error) {
	for _, p := range f.policies {
		if p.Name == name {
			cp := p
			return &cp, nil
		}
	}
	return nil, repository.ErrNotFound
}
func (f fakePolicyRepo) List(ctx context.Context, limit, offset int) ([]models.Policy, int, error) {
	var items []models.Policy
	for _, p := range f.policies {
		items = append(items, p)
	}
	return items, len(items), nil
}
func (f fakePolicyRepo) Create(ctx context.Context, p *models.Policy) error { return nil }
func (f fakePolicyRepo) Update(ctx context.Context, p *models.Policy) error { return nil }
func (f fakePolicyRepo) Delete(ctx context.Context, id string) error        { return nil }
func (f fakePolicyRepo) SetStatus(ctx context.Context, id string, status models.PolicyStatus) error {
	return nil
}

type fakePolicyRuleRepo struct {
	rules map[string][]models.PolicyRule
}

func (f fakePolicyRuleRepo) ListByPolicy(ctx context.Context, policyID string) ([]models.PolicyRule, error) {
	return f.rules[policyID], nil
}
func (f fakePolicyRuleRepo) Create(ctx context.Context, rule *models.PolicyRule) error { return nil }
func (f fakePolicyRuleRepo) Delete(ctx context.Context, id string) error               { return nil }
func (f fakePolicyRuleRepo) DeleteByPolicy(ctx context.Context, policyID string) error {
	return nil
}

type fakeUserGroupRepo struct {
	groups []models.Group
}

func (f fakeUserGroupRepo) AddUser(ctx context.Context, groupID, userID string) error { return nil }
func (f fakeUserGroupRepo) RemoveUser(ctx context.Context, groupID, userID string) error {
	return nil
}
func (f fakeUserGroupRepo) ListUsers(ctx context.Context, groupID string, limit, offset int) ([]models.User, int, error) {
	return nil, 0, nil
}
func (f fakeUserGroupRepo) ListGroups(ctx context.Context, userID string) ([]models.Group, error) {
	return f.groups, nil
}

type fakeGroupPolicyRepo struct {
	policies map[string]string
}

func (f fakeGroupPolicyRepo) SetPolicy(ctx context.Context, groupID, policyID string) error {
	return nil
}
func (f fakeGroupPolicyRepo) GetPolicy(ctx context.Context, groupID string) (string, error) {
	if id, ok := f.policies[groupID]; ok {
		return id, nil
	}
	return "", repository.ErrNotFound
}
func (f fakeGroupPolicyRepo) ClearPolicy(ctx context.Context, groupID string) error { return nil }

type fakeOTPSecretRepo struct {
	secret     *models.OTPSecret
	created    *models.OTPSecret
	disabledID string
}

func (f *fakeOTPSecretRepo) GetActiveByUser(ctx context.Context, userID string) (*models.OTPSecret, error) {
	if f.secret != nil && f.secret.UserID == userID && f.secret.Enabled {
		return f.secret, nil
	}
	return nil, repository.ErrNotFound
}
func (f *fakeOTPSecretRepo) Create(ctx context.Context, s *models.OTPSecret) error {
	f.created = s
	return nil
}
func (f *fakeOTPSecretRepo) Disable(ctx context.Context, id string) error {
	f.disabledID = id
	return nil
}

type fakeDeviceRepo struct {
	upserted *models.Device
}

func (f *fakeDeviceRepo) ListByUser(ctx context.Context, userID string) ([]models.Device, error) {
	return nil, nil
}

func (f *fakeDeviceRepo) Upsert(ctx context.Context, d *models.Device) error {
	f.upserted = d
	return nil
}

func (f *fakeDeviceRepo) Disable(ctx context.Context, id string) error {
	return nil
}

type fakeRecoveryCodeRepo struct {
	codes        map[string]bool
	createdCount int
	consumed     bool
}

func (f *fakeRecoveryCodeRepo) DeleteByUser(ctx context.Context, userID string) error {
	f.codes = map[string]bool{}
	return nil
}

func (f *fakeRecoveryCodeRepo) CreateMany(ctx context.Context, codes []models.RecoveryCode) error {
	if f.codes == nil {
		f.codes = map[string]bool{}
	}
	for _, code := range codes {
		f.codes[code.CodeHash] = false
		f.createdCount++
	}
	return nil
}

func (f *fakeRecoveryCodeRepo) Consume(ctx context.Context, userID string, codeHash string, usedAt time.Time) (bool, error) {
	used, ok := f.codes[codeHash]
	if !ok || used {
		return false, nil
	}
	f.codes[codeHash] = true
	f.consumed = true
	return true, nil
}

type fakeLDAPAuth struct {
	err error
}

func (f fakeLDAPAuth) Authenticate(ctx context.Context, userDN string, password string) error {
	return f.err
}

type recordUserRepo struct {
	created *models.User
}

func (r *recordUserRepo) GetByID(ctx context.Context, id string) (*models.User, error) {
	return nil, repository.ErrNotFound
}
func (r *recordUserRepo) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	return nil, repository.ErrNotFound
}
func (r *recordUserRepo) GetByUsernameAndRole(ctx context.Context, username string, role models.UserRole) (*models.User, error) {
	return nil, repository.ErrNotFound
}
func (r *recordUserRepo) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	return nil, repository.ErrNotFound
}
func (r *recordUserRepo) GetByPhone(ctx context.Context, phone string) (*models.User, error) {
	return nil, repository.ErrNotFound
}
func (r *recordUserRepo) List(ctx context.Context, filter repository.UserListFilter, limit, offset int) ([]models.User, int, error) {
	return nil, 0, nil
}
func (r *recordUserRepo) Create(ctx context.Context, u *models.User) error {
	r.created = u
	return nil
}
func (r *recordUserRepo) Update(ctx context.Context, u *models.User) error { return nil }
func (r *recordUserRepo) Delete(ctx context.Context, id string) error      { return nil }
func (r *recordUserRepo) SetStatus(ctx context.Context, id string, status models.UserStatus) error {
	return nil
}

type fakeInviteRepo struct {
	items        map[string]*models.Invite
	usedID       string
	usedBy       string
	expiredCount int64
}

func (f *fakeInviteRepo) Create(ctx context.Context, invite *models.Invite) error {
	if f.items == nil {
		f.items = map[string]*models.Invite{}
	}
	f.items[invite.TokenHash] = invite
	return nil
}
func (f *fakeInviteRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*models.Invite, error) {
	item, ok := f.items[tokenHash]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return item, nil
}
func (f *fakeInviteRepo) MarkUsed(ctx context.Context, id string, userID string, usedAt time.Time) error {
	f.usedID = id
	f.usedBy = userID
	return nil
}
func (f *fakeInviteRepo) MarkExpired(ctx context.Context, now time.Time) (int64, error) {
	f.expiredCount++
	return f.expiredCount, nil
}

func (f *fakeSessionRepo) Create(ctx context.Context, s *models.UserSession) error {
	if f.items == nil {
		f.items = map[string]models.UserSession{}
	}
	f.items[s.RefreshTokenHash] = *s
	return nil
}
func (f *fakeSessionRepo) Revoke(ctx context.Context, id string, revokedAt time.Time) error {
	f.revokedID = id
	return nil
}
func (f *fakeSessionRepo) GetByRefreshHash(ctx context.Context, hash string) (*models.UserSession, error) {
	s, ok := f.items[hash]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return &s, nil
}

func (f *fakeSessionRepo) GetByID(ctx context.Context, id string) (*models.UserSession, error) {
	for _, s := range f.items {
		if s.ID == id {
			return &s, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (f *fakeSessionRepo) RotateRefreshHash(ctx context.Context, id string, newHash string) error {
	for key, s := range f.items {
		if s.ID == id {
			delete(f.items, key)
			s.RefreshTokenHash = newHash
			f.items[newHash] = s
			return nil
		}
	}
	return repository.ErrNotFound
}

func (f *fakeSessionRepo) List(ctx context.Context, filter repository.SessionListFilter, limit, offset int) ([]models.UserSession, int, error) {
	var out []models.UserSession
	for _, s := range f.items {
		if filter.UserID == "" || s.UserID == filter.UserID {
			out = append(out, s)
		}
	}
	return out, len(out), nil
}

func (f *fakeSessionRepo) RevokeAllByUser(ctx context.Context, userID string, exceptSessionID string, revokedAt time.Time) error {
	for key, s := range f.items {
		if s.UserID != userID || s.ID == exceptSessionID {
			continue
		}
		s.RevokedAt = &revokedAt
		f.items[key] = s
	}
	return nil
}

func (f *fakeSessionRepo) Touch(ctx context.Context, id string, seenAt time.Time) error {
	return nil
}
