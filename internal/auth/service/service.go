package service

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "time"

    "golang.org/x/crypto/bcrypt"

    "github.com/qmish/2FA/internal/auth/providers"
    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/models"
    "github.com/qmish/2FA/internal/repository"
)

var (
    ErrInvalidCredentials = errors.New("invalid credentials")
    ErrChallengeNotFound  = errors.New("challenge not found")
    ErrChallengeExpired   = errors.New("challenge expired")
    ErrSecondFactorFailed = errors.New("second factor failed")
    ErrSessionNotFound    = errors.New("session not found")
    ErrSessionExpired     = errors.New("session expired")
)

type Service struct {
    users      repository.UserRepository
    challenges repository.ChallengeRepository
    sessions   repository.SessionRepository
    providers  *providers.Registry
    now        func() time.Time
    ttl        time.Duration
    sessionTTL time.Duration
    codeGen    func() string
    tokenGen   func() string
}

func NewService(
    users repository.UserRepository,
    challenges repository.ChallengeRepository,
    sessions repository.SessionRepository,
    providers *providers.Registry,
    ttl time.Duration,
    sessionTTL time.Duration,
) *Service {
    return &Service{
        users:      users,
        challenges: challenges,
        sessions:   sessions,
        providers:  providers,
        now:        time.Now,
        ttl:        ttl,
        sessionTTL: sessionTTL,
        codeGen:    generateCode,
        tokenGen:   newToken,
    }
}

func (s *Service) Login(ctx context.Context, req dto.LoginRequest) (dto.LoginResponse, error) {
    user, err := s.users.GetByUsername(ctx, req.Username)
    if err != nil {
        return dto.LoginResponse{}, ErrInvalidCredentials
    }
    if user.Status != models.UserActive {
        return dto.LoginResponse{}, ErrInvalidCredentials
    }
    if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
        return dto.LoginResponse{}, ErrInvalidCredentials
    }

    method := models.MethodOTP
    if req.Method != "" {
        method = req.Method
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
        switch method {
        case models.MethodOTP:
            if _, err := s.providers.SendSMS(ctx, "", user.Phone, code); err == nil {
                _ = s.challenges.UpdateStatus(ctx, challengeID, models.ChallengeSent)
            }
        case models.MethodCall:
            if _, err := s.providers.StartCall(ctx, "", user.Phone, code); err == nil {
                _ = s.challenges.UpdateStatus(ctx, challengeID, models.ChallengeSent)
            }
        case models.MethodPush:
            if _, err := s.providers.SendPush(ctx, "", user.ID, "2FA", code); err == nil {
                _ = s.challenges.UpdateStatus(ctx, challengeID, models.ChallengeSent)
            }
        }
    }

    return dto.LoginResponse{
        UserID:      user.ID,
        ChallengeID: challengeID,
        Method:      method,
        ExpiresAt:   expiresAt.Unix(),
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
    if s.now().After(challenge.ExpiresAt) {
        _ = s.challenges.UpdateStatus(ctx, challenge.ID, models.ChallengeExpired)
        return dto.TokenPair{}, ErrChallengeExpired
    }
    if challenge.Method == models.MethodOTP {
        if hash(req.Code) != challenge.CodeHash {
            _ = s.challenges.UpdateStatus(ctx, challenge.ID, models.ChallengeDenied)
            return dto.TokenPair{}, ErrSecondFactorFailed
        }
    } else {
        if req.Code == "" {
            _ = s.challenges.UpdateStatus(ctx, challenge.ID, models.ChallengeDenied)
            return dto.TokenPair{}, ErrSecondFactorFailed
        }
    }

    _ = s.challenges.UpdateStatus(ctx, challenge.ID, models.ChallengeApproved)

    now := s.now()
    refresh := newToken()
    session := &models.UserSession{
        ID:               s.tokenGen(),
        UserID:           challenge.UserID,
        RefreshTokenHash: hash(refresh),
        IP:               "",
        UserAgent:        "",
        ExpiresAt:        now.Add(s.sessionTTL),
        CreatedAt:        now,
    }
    if err := s.sessions.Create(ctx, session); err != nil {
        return dto.TokenPair{}, err
    }
    return dto.TokenPair{
        AccessToken:  s.tokenGen(),
        RefreshToken: refresh,
        ExpiresIn:    int64(s.sessionTTL.Seconds()),
    }, nil
}

func (s *Service) Refresh(ctx context.Context, req dto.RefreshRequest) (dto.TokenPair, error) {
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
    return dto.TokenPair{
        AccessToken:  newToken(),
        RefreshToken: req.RefreshToken,
        ExpiresIn:    int64(s.sessionTTL.Seconds()),
    }, nil
}

func (s *Service) Logout(ctx context.Context, sessionID string) error {
    return s.sessions.Revoke(ctx, sessionID, s.now())
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
