package auth

import (
    "context"
    "errors"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "golang.org/x/crypto/bcrypt"

    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/models"
    "github.com/qmish/2FA/internal/repository"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type AdminClaims struct {
    Role string `json:"role"`
    jwt.RegisteredClaims
}

type Service struct {
    issuer       string
    secret       []byte
    ttl          time.Duration
    users        repository.UserRepository
}

func NewService(issuer string, secret []byte, ttl time.Duration, users repository.UserRepository) *Service {
    return &Service{
        issuer:       issuer,
        secret:       secret,
        ttl:          ttl,
        users:        users,
    }
}

func (s *Service) Login(ctx context.Context, req dto.AdminLoginRequest) (dto.TokenPair, error) {
    user, err := s.users.GetByUsernameAndRole(ctx, req.Username, models.RoleAdmin)
    if err != nil {
        return dto.TokenPair{}, ErrInvalidCredentials
    }
    if user.Status != models.UserActive {
        return dto.TokenPair{}, ErrInvalidCredentials
    }
    if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
        return dto.TokenPair{}, ErrInvalidCredentials
    }
    now := time.Now()
    claims := AdminClaims{
        Role: string(user.Role),
        RegisteredClaims: jwt.RegisteredClaims{
            Issuer:    s.issuer,
            Subject:   user.Username,
            ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
            IssuedAt:  jwt.NewNumericDate(now),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    signed, err := token.SignedString(s.secret)
    if err != nil {
        return dto.TokenPair{}, err
    }
    return dto.TokenPair{
        AccessToken: signed,
        ExpiresIn:   int64(s.ttl.Seconds()),
    }, nil
}

func (s *Service) Validate(tokenStr string) error {
    _, err := s.ParseClaims(tokenStr)
    return err
}

func (s *Service) ParseClaims(tokenStr string) (*AdminClaims, error) {
    token, err := jwt.ParseWithClaims(tokenStr, &AdminClaims{}, func(token *jwt.Token) (any, error) {
        return s.secret, nil
    })
    if err != nil {
        return nil, err
    }
    claims, ok := token.Claims.(*AdminClaims)
    if !ok || !token.Valid {
        return nil, ErrInvalidCredentials
    }
    return claims, nil
}
