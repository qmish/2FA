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

    "github.com/qmish/2FA/internal/auth/providers"
    "github.com/qmish/2FA/internal/models"
    "github.com/qmish/2FA/internal/radius/protocol"
    "github.com/qmish/2FA/internal/repository"
    "github.com/qmish/2FA/pkg/validator"
)

type ResponseCode string

const (
    AccessAccept ResponseCode = "Access-Accept"
    AccessReject ResponseCode = "Access-Reject"
)

var ErrSecondFactorFailed = errors.New("second_factor_failed")
var ErrChallengeExpired = errors.New("challenge_expired")
var ErrChallengeNotFound = errors.New("challenge_not_found")

type AccessResponse struct {
    Code    ResponseCode
    Message string
}

type RadiusService struct {
    users      repository.UserRepository
    challenges repository.ChallengeRepository
    providers  *providers.Registry
    logins     repository.LoginHistoryRepository
    audits     repository.AuditRepository
    now        func() time.Time
    ttl        time.Duration
}

func NewRadiusService(
    users repository.UserRepository,
    challenges repository.ChallengeRepository,
    providers *providers.Registry,
    logins repository.LoginHistoryRepository,
    audits repository.AuditRepository,
    ttl time.Duration,
) *RadiusService {
    return &RadiusService{
        users:      users,
        challenges: challenges,
        providers:  providers,
        logins:     logins,
        audits:     audits,
        now:        time.Now,
        ttl:        ttl,
    }
}

func (s *RadiusService) HandleAccessRequest(ctx context.Context, req protocol.AccessRequest) AccessResponse {
    user, err := s.lookupUser(ctx, req.Username)
    if err != nil || user.Status != models.UserActive {
        s.recordLogin(ctx, "", models.AuthDeny)
        return AccessResponse{Code: AccessReject, Message: "invalid_credentials"}
    }
    password, otp := splitPassword(req.Password)
    if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
        s.recordLogin(ctx, user.ID, models.AuthDeny)
        return AccessResponse{Code: AccessReject, Message: "invalid_credentials"}
    }
    if otp == "" {
        if err := s.sendOTP(ctx, user); err != nil {
            s.recordLogin(ctx, user.ID, models.AuthError)
            return AccessResponse{Code: AccessReject, Message: "otp_failed"}
        }
        s.recordLogin(ctx, user.ID, models.AuthTimeout)
        return AccessResponse{Code: AccessReject, Message: "otp_required"}
    }
    if err := s.verifyOTP(ctx, user, otp); err != nil {
        s.recordLogin(ctx, user.ID, models.AuthDeny)
        return AccessResponse{Code: AccessReject, Message: err.Error()}
    }
    s.recordLogin(ctx, user.ID, models.AuthSuccess)
    return AccessResponse{Code: AccessAccept, Message: "ok"}
}

func (s *RadiusService) lookupUser(ctx context.Context, username string) (*models.User, error) {
    username = strings.TrimSpace(username)
    if username == "" {
        return nil, repository.ErrNotFound
    }
    normalizedEmail := validator.NormalizeEmail(username)
    if validator.IsEmailValid(normalizedEmail) {
        return s.users.GetByEmail(ctx, normalizedEmail)
    }
    normalizedPhone := validator.NormalizePhone(username)
    if validator.IsPhoneValid(normalizedPhone) {
        return s.users.GetByPhone(ctx, normalizedPhone)
    }
    return s.users.GetByUsername(ctx, username)
}

func splitPassword(password string) (string, string) {
    password = strings.TrimSpace(password)
    idx := strings.LastIndex(password, ":")
    if idx < 0 {
        return password, ""
    }
    left := strings.TrimSpace(password[:idx])
    right := strings.TrimSpace(password[idx+1:])
    if right == "" {
        return password, ""
    }
    return left, right
}

func (s *RadiusService) sendOTP(ctx context.Context, user *models.User) error {
    if s.challenges == nil {
        return repository.ErrNotFound
    }
    now := s.now()
    expiresAt := now.Add(s.ttl)
    code := generateCode()
    challenge := &models.Challenge{
        ID:        newToken(),
        UserID:    user.ID,
        Method:    models.MethodOTP,
        Status:    models.ChallengeCreated,
        CodeHash:  hash(code),
        ExpiresAt: expiresAt,
        CreatedAt: now,
        UpdatedAt: now,
    }
    if err := s.challenges.Create(ctx, challenge); err != nil {
        return err
    }
    if s.providers == nil {
        return nil
    }
    providerID, err := s.providers.SendSMS(ctx, "", user.Phone, code)
    if err != nil {
        _ = s.challenges.UpdateStatus(ctx, challenge.ID, models.ChallengeFailed)
        return err
    }
    if providerID != "" {
        _ = s.challenges.UpdateDelivery(ctx, challenge.ID, providerID, models.ChallengeSent)
    } else {
        _ = s.challenges.UpdateStatus(ctx, challenge.ID, models.ChallengeSent)
    }
    return nil
}

func (s *RadiusService) verifyOTP(ctx context.Context, user *models.User, otp string) error {
    if s.challenges == nil {
        return ErrChallengeNotFound
    }
    challenge, err := s.challenges.GetActiveByUserAndMethod(ctx, user.ID, models.MethodOTP)
    if err != nil {
        return ErrChallengeNotFound
    }
    if s.now().After(challenge.ExpiresAt) {
        _ = s.challenges.UpdateStatus(ctx, challenge.ID, models.ChallengeExpired)
        return ErrChallengeExpired
    }
    if hash(otp) != challenge.CodeHash {
        _ = s.challenges.UpdateStatus(ctx, challenge.ID, models.ChallengeDenied)
        return ErrSecondFactorFailed
    }
    _ = s.challenges.UpdateStatus(ctx, challenge.ID, models.ChallengeApproved)
    return nil
}

func (s *RadiusService) recordLogin(ctx context.Context, userID string, result models.AuthResult) {
    if s.logins != nil {
        _ = s.logins.Create(ctx, &models.LoginHistory{
            ID:        newToken(),
            UserID:    userID,
            Channel:   models.ChannelVPN,
            Result:    result,
            CreatedAt: s.now(),
        })
    }
    if s.audits != nil && userID != "" {
        _ = s.audits.Create(ctx, &models.AuditEvent{
            ID:          newToken(),
            ActorUserID: userID,
            Action:      models.AuditLogin,
            EntityType:  models.AuditEntityUser,
            EntityID:    userID,
            CreatedAt:   s.now(),
        })
    }
}

func hash(v string) string {
    sum := sha256.Sum256([]byte(v))
    return hex.EncodeToString(sum[:])
}

func generateCode() string {
    b := make([]byte, 3)
    if _, err := rand.Read(b); err != nil {
        return "000000"
    }
    return hex.EncodeToString(b)[:6]
}

func newToken() string {
    b := make([]byte, 16)
    if _, err := rand.Read(b); err != nil {
        return ""
    }
    return hex.EncodeToString(b)
}
