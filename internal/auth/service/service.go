package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/qmish/2FA/internal/api/metrics"
	authjwt "github.com/qmish/2FA/internal/auth/jwt"
	"github.com/qmish/2FA/internal/auth/ldap"
	"github.com/qmish/2FA/internal/auth/providers"
	"github.com/qmish/2FA/internal/dto"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/internal/repository"
	"github.com/qmish/2FA/pkg/validator"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrChallengeNotFound  = errors.New("challenge not found")
	ErrChallengeExpired   = errors.New("challenge expired")
	ErrSecondFactorFailed = errors.New("second factor failed")
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionExpired     = errors.New("session expired")
	ErrForbidden          = errors.New("forbidden")
	ErrRateLimited        = errors.New("rate limited")
	ErrNotFound           = errors.New("not found")
	ErrNotConfigured      = errors.New("not configured")
	ErrConflict           = errors.New("conflict")
	ErrInviteInvalid      = errors.New("invite invalid")
)

type Service struct {
	users         repository.UserRepository
	challenges    repository.ChallengeRepository
	sessions      repository.SessionRepository
	providers     *providers.Registry
	lockouts      repository.LockoutRepository
	logins        repository.LoginHistoryRepository
	audits        repository.AuditRepository
	jwt           *authjwt.Service
	policies      repository.PolicyRepository
	policyRules   repository.PolicyRuleRepository
	userGroups    repository.UserGroupRepository
	groupPolicies repository.GroupPolicyRepository
	otpSecrets    repository.OTPSecretRepository
	invites       repository.InviteRepository
	totpIssuer    string
	totpDigits    int
	totpPeriod    int
	ldapAuth      ldap.Authenticator
	now           func() time.Time
	ttl           time.Duration
	sessionTTL    time.Duration
	codeGen       func() string
	tokenGen      func() string
}

func NewService(
	users repository.UserRepository,
	challenges repository.ChallengeRepository,
	sessions repository.SessionRepository,
	providers *providers.Registry,
	lockouts repository.LockoutRepository,
	logins repository.LoginHistoryRepository,
	audits repository.AuditRepository,
	jwtSvc *authjwt.Service,
	ttl time.Duration,
	sessionTTL time.Duration,
) *Service {
	return &Service{
		users:      users,
		challenges: challenges,
		sessions:   sessions,
		providers:  providers,
		lockouts:   lockouts,
		logins:     logins,
		audits:     audits,
		jwt:        jwtSvc,
		now:        time.Now,
		ttl:        ttl,
		sessionTTL: sessionTTL,
		codeGen:    generateCode,
		tokenGen:   newToken,
	}
}

func (s *Service) WithPolicies(
	policies repository.PolicyRepository,
	policyRules repository.PolicyRuleRepository,
	userGroups repository.UserGroupRepository,
	groupPolicies repository.GroupPolicyRepository,
) *Service {
	s.policies = policies
	s.policyRules = policyRules
	s.userGroups = userGroups
	s.groupPolicies = groupPolicies
	return s
}

func (s *Service) WithOTPSecrets(repo repository.OTPSecretRepository) *Service {
	s.otpSecrets = repo
	return s
}

func (s *Service) WithTOTPConfig(issuer string, digits int, period int) *Service {
	s.totpIssuer = issuer
	s.totpDigits = digits
	s.totpPeriod = period
	return s
}

func (s *Service) WithLDAPAuth(auth ldap.Authenticator) *Service {
	s.ldapAuth = auth
	return s
}

func (s *Service) WithInvites(invites repository.InviteRepository) *Service {
	s.invites = invites
	return s
}

func (s *Service) Login(ctx context.Context, req dto.LoginRequest) (dto.LoginResponse, error) {
	username := strings.TrimSpace(req.Username)
	if username == "" {
		return dto.LoginResponse{}, ErrInvalidCredentials
	}
	if s.lockouts != nil && req.IP != "" {
		if _, err := s.lockouts.GetActive(ctx, "", req.IP, s.now()); err == nil {
			metrics.Default.IncLockoutActive()
			return dto.LoginResponse{}, ErrForbidden
		}
	}
	var (
		user *models.User
		err  error
	)
	normalizedEmail := validator.NormalizeEmail(username)
	if validator.IsEmailValid(normalizedEmail) {
		user, err = s.users.GetByEmail(ctx, normalizedEmail)
	} else {
		normalizedPhone := validator.NormalizePhone(username)
		if validator.IsPhoneValid(normalizedPhone) {
			user, err = s.users.GetByPhone(ctx, normalizedPhone)
		} else {
			user, err = s.users.GetByUsername(ctx, username)
		}
	}
	if err != nil {
		return dto.LoginResponse{}, ErrInvalidCredentials
	}
	if s.lockouts != nil && req.IP != "" {
		if _, err := s.lockouts.GetActive(ctx, user.ID, req.IP, s.now()); err == nil {
			metrics.Default.IncLockoutActive()
			return dto.LoginResponse{}, ErrForbidden
		}
	}
	if user.Status != models.UserActive {
		return dto.LoginResponse{}, ErrInvalidCredentials
	}
	if user.AdDN != "" && s.ldapAuth != nil {
		if err := s.ldapAuth.Authenticate(ctx, user.AdDN, req.Password); err != nil {
			s.recordLoginFailure(ctx, user.ID, req.Channel, req.IP)
			return dto.LoginResponse{}, ErrInvalidCredentials
		}
	} else {
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
			s.recordLoginFailure(ctx, user.ID, req.Channel, req.IP)
			return dto.LoginResponse{}, ErrInvalidCredentials
		}
	}
	s.recordLoginResult(ctx, user.ID, req.Channel, req.IP, models.AuthSuccess)

	method := models.MethodOTP
	if req.Method != "" {
		method = req.Method
	}
	if !s.isPolicyAllowed(ctx, user, req, method) {
		return dto.LoginResponse{}, ErrForbidden
	}
	challengeID := s.tokenGen()
	now := s.now()
	expiresAt := now.Add(s.ttl)
	code := s.codeGen()
	codeHash := hash(code)

	challenge := &models.Challenge{
		ID:        challengeID,
		UserID:    user.ID,
		Method:    method,
		Status:    models.ChallengeCreated,
		CodeHash:  codeHash,
		ExpiresAt: expiresAt,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.challenges.Create(ctx, challenge); err != nil {
		return dto.LoginResponse{}, err
	}

	if s.providers != nil {
		providerID := ""
		sendErr := error(nil)
		switch method {
		case models.MethodOTP:
			if !validator.IsPhoneValid(user.Phone) {
				_ = s.challenges.UpdateStatus(ctx, challengeID, models.ChallengeFailed)
				return dto.LoginResponse{}, ErrSecondFactorFailed
			}
			providerID, sendErr = s.providers.SendSMS(ctx, "", user.Phone, code)
		case models.MethodCall:
			if !validator.IsPhoneValid(user.Phone) {
				_ = s.challenges.UpdateStatus(ctx, challengeID, models.ChallengeFailed)
				return dto.LoginResponse{}, ErrSecondFactorFailed
			}
			providerID, sendErr = s.providers.StartCall(ctx, "", user.Phone, code)
		case models.MethodPush:
			providerID, sendErr = s.providers.SendPush(ctx, "", user.ID, "2FA", code)
		case models.MethodTOTP:
			// TOTP не требует внешнего провайдера
		}
		if sendErr != nil {
			_ = s.challenges.UpdateStatus(ctx, challengeID, models.ChallengeFailed)
			return dto.LoginResponse{}, ErrSecondFactorFailed
		}
		if providerID != "" {
			_ = s.challenges.UpdateDelivery(ctx, challengeID, providerID, models.ChallengeSent)
		} else {
			_ = s.challenges.UpdateStatus(ctx, challengeID, models.ChallengeSent)
		}
		challenge.Status = models.ChallengeSent
	}

	return dto.LoginResponse{
		UserID:      user.ID,
		ChallengeID: challengeID,
		Method:      method,
		ExpiresAt:   expiresAt.Unix(),
		Status:      challenge.Status,
	}, nil
}

func (s *Service) VerifySecondFactor(ctx context.Context, req dto.VerifyRequest) (dto.TokenPair, error) {
	challenge, err := s.challenges.GetByID(ctx, req.ChallengeID)
	if err != nil {
		return dto.TokenPair{}, ErrChallengeNotFound
	}
	if challenge.UserID != req.UserID {
		return dto.TokenPair{}, ErrChallengeNotFound
	}
	if req.Method != "" && req.Method != challenge.Method {
		_ = s.challenges.UpdateStatus(ctx, challenge.ID, models.ChallengeDenied)
		s.recordSecondFactor(ctx, challenge.UserID, challenge.ID, models.AuditSecondFactorDeny, req.IP, string(challenge.Method))
		return dto.TokenPair{}, ErrSecondFactorFailed
	}
	switch challenge.Status {
	case models.ChallengeCreated, models.ChallengeSent, models.ChallengePending:
	case models.ChallengeExpired:
		s.recordSecondFactor(ctx, challenge.UserID, challenge.ID, models.AuditSecondFactorDeny, req.IP, string(challenge.Method))
		return dto.TokenPair{}, ErrChallengeExpired
	default:
		s.recordSecondFactor(ctx, challenge.UserID, challenge.ID, models.AuditSecondFactorDeny, req.IP, string(challenge.Method))
		return dto.TokenPair{}, ErrSecondFactorFailed
	}
	if s.now().After(challenge.ExpiresAt) {
		_ = s.challenges.UpdateStatus(ctx, challenge.ID, models.ChallengeExpired)
		s.recordSecondFactor(ctx, challenge.UserID, challenge.ID, models.AuditSecondFactorDeny, req.IP, string(challenge.Method))
		return dto.TokenPair{}, ErrChallengeExpired
	}
	switch challenge.Method {
	case models.MethodOTP:
		if hash(req.Code) != challenge.CodeHash {
			_ = s.challenges.UpdateStatus(ctx, challenge.ID, models.ChallengeDenied)
			s.recordLoginFailure(ctx, challenge.UserID, "", req.IP)
			s.recordSecondFactor(ctx, challenge.UserID, challenge.ID, models.AuditSecondFactorDeny, req.IP, string(challenge.Method))
			return dto.TokenPair{}, ErrSecondFactorFailed
		}
	case models.MethodTOTP:
		if !s.validateTOTP(ctx, challenge.UserID, req.Code) {
			_ = s.challenges.UpdateStatus(ctx, challenge.ID, models.ChallengeDenied)
			s.recordLoginFailure(ctx, challenge.UserID, "", req.IP)
			s.recordSecondFactor(ctx, challenge.UserID, challenge.ID, models.AuditSecondFactorDeny, req.IP, string(challenge.Method))
			return dto.TokenPair{}, ErrSecondFactorFailed
		}
	default:
		if req.Code == "" {
			_ = s.challenges.UpdateStatus(ctx, challenge.ID, models.ChallengeDenied)
			s.recordLoginFailure(ctx, challenge.UserID, "", req.IP)
			s.recordSecondFactor(ctx, challenge.UserID, challenge.ID, models.AuditSecondFactorDeny, req.IP, string(challenge.Method))
			return dto.TokenPair{}, ErrSecondFactorFailed
		}
	}

	_ = s.challenges.UpdateStatus(ctx, challenge.ID, models.ChallengeApproved)
	s.recordSecondFactor(ctx, challenge.UserID, challenge.ID, models.AuditSecondFactorApprove, req.IP, string(challenge.Method))

	now := s.now()
	refresh := newToken()
	session := &models.UserSession{
		ID:               s.tokenGen(),
		UserID:           challenge.UserID,
		RefreshTokenHash: hash(refresh),
		IP:               req.IP,
		UserAgent:        req.UserAgent,
		ExpiresAt:        now.Add(s.sessionTTL),
		CreatedAt:        now,
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return dto.TokenPair{}, err
	}
	if s.jwt == nil {
		return dto.TokenPair{}, ErrSecondFactorFailed
	}
	accessToken, accessExp, err := s.jwt.Sign(session.UserID, session.ID)
	if err != nil {
		return dto.TokenPair{}, err
	}
	return dto.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refresh,
		ExpiresIn:    int64(accessExp.Sub(s.now()).Seconds()),
	}, nil
}

func (s *Service) Refresh(ctx context.Context, req dto.RefreshRequest, ip string) (dto.TokenPair, error) {
	sess, err := s.sessions.GetByRefreshHash(ctx, hash(req.RefreshToken))
	if err != nil {
		return dto.TokenPair{}, ErrSessionNotFound
	}
	if sess.RevokedAt != nil {
		return dto.TokenPair{}, ErrSessionNotFound
	}
	if s.now().After(sess.ExpiresAt) {
		return dto.TokenPair{}, ErrSessionExpired
	}
	if s.jwt == nil {
		return dto.TokenPair{}, ErrSessionNotFound
	}
	newRefresh := newToken()
	if err := s.sessions.RotateRefreshHash(ctx, sess.ID, hash(newRefresh)); err != nil {
		return dto.TokenPair{}, err
	}
	if s.audits != nil && sess.UserID != "" {
		_ = s.audits.Create(ctx, &models.AuditEvent{
			ID:          s.tokenGen(),
			ActorUserID: sess.UserID,
			Action:      models.AuditRefresh,
			EntityType:  models.AuditEntitySession,
			EntityID:    sess.ID,
			IP:          ip,
			CreatedAt:   s.now(),
		})
	}
	accessToken, accessExp, err := s.jwt.Sign(sess.UserID, sess.ID)
	if err != nil {
		return dto.TokenPair{}, err
	}
	return dto.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRefresh,
		ExpiresIn:    int64(accessExp.Sub(s.now()).Seconds()),
	}, nil
}

func (s *Service) Logout(ctx context.Context, userID string, sessionID string, ip string) error {
	sess, err := s.sessions.GetByID(ctx, sessionID)
	if err != nil || sess.UserID != userID {
		return ErrForbidden
	}
	if err := s.sessions.Revoke(ctx, sessionID, s.now()); err != nil {
		return err
	}
	if s.audits != nil && userID != "" {
		_ = s.audits.Create(ctx, &models.AuditEvent{
			ID:          s.tokenGen(),
			ActorUserID: userID,
			Action:      models.AuditLogout,
			EntityType:  models.AuditEntitySession,
			EntityID:    sessionID,
			IP:          ip,
			CreatedAt:   s.now(),
		})
	}
	return nil
}

func (s *Service) recordLoginResult(ctx context.Context, userID string, channel models.AuthChannel, ip string, result models.AuthResult) {
	if s.logins == nil {
		if s.audits == nil || userID == "" {
			return
		}
	}
	if s.logins != nil {
		_ = s.logins.Create(ctx, &models.LoginHistory{
			ID:        s.tokenGen(),
			UserID:    userID,
			Channel:   channel,
			Result:    result,
			IP:        ip,
			CreatedAt: s.now(),
		})
	}
	if s.audits != nil && userID != "" {
		_ = s.audits.Create(ctx, &models.AuditEvent{
			ID:          s.tokenGen(),
			ActorUserID: userID,
			Action:      models.AuditLogin,
			EntityType:  models.AuditEntityUser,
			EntityID:    userID,
			Payload:     string(result),
			IP:          ip,
			CreatedAt:   s.now(),
		})
	}
}

func (s *Service) recordLoginFailure(ctx context.Context, userID string, channel models.AuthChannel, ip string) {
	s.recordLoginResult(ctx, userID, channel, ip, models.AuthDeny)
	if s.lockouts == nil || s.logins == nil || userID == "" {
		return
	}
	since := s.now().Add(-time.Duration(models.AttemptsWindowSeconds) * time.Second)
	count, err := s.logins.CountFailures(ctx, userID, since)
	if err != nil {
		return
	}
	if count+1 < models.MaxAttemptsPerWindow {
		return
	}
	expiresAt := s.now().Add(time.Duration(models.LockoutSeconds) * time.Second)
	lockout := &models.Lockout{
		ID:        s.tokenGen(),
		UserID:    userID,
		IP:        ip,
		Reason:    "too_many_attempts",
		ExpiresAt: expiresAt,
		CreatedAt: s.now(),
	}
	if err := s.lockouts.Create(ctx, lockout); err != nil {
		return
	}
	if s.audits != nil && userID != "" {
		_ = s.audits.Create(ctx, &models.AuditEvent{
			ID:          s.tokenGen(),
			ActorUserID: userID,
			Action:      models.AuditLockoutCreate,
			EntityType:  models.AuditEntityLockout,
			EntityID:    lockout.ID,
			Payload:     lockout.Reason,
			IP:          ip,
			CreatedAt:   s.now(),
		})
	}
	metrics.Default.IncLockoutCreated()
}

func (s *Service) recordSecondFactor(ctx context.Context, userID string, challengeID string, action models.AuditAction, ip string, payload string) {
	if s.audits == nil || userID == "" {
		return
	}
	_ = s.audits.Create(ctx, &models.AuditEvent{
		ID:          s.tokenGen(),
		ActorUserID: userID,
		Action:      action,
		EntityType:  models.AuditEntityChallenge,
		EntityID:    challengeID,
		Payload:     payload,
		IP:          ip,
		CreatedAt:   s.now(),
	})
}

func newID() string {
	return newToken()
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func generateCode() string {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "000000"
	}
	return hex.EncodeToString(b)[:6]
}

func hash(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
