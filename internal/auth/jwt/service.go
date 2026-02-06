package jwt

import (
    "errors"
    "time"

    jwtlib "github.com/golang-jwt/jwt/v5"
)

var ErrInvalidToken = errors.New("invalid token")

type Claims struct {
    SessionID string `json:"sid"`
    jwtlib.RegisteredClaims
}

type Service struct {
    issuer string
    secret []byte
    ttl    time.Duration
}

func NewService(issuer string, secret []byte, ttl time.Duration) *Service {
    return &Service{
        issuer: issuer,
        secret: secret,
        ttl:    ttl,
    }
}

func (s *Service) Sign(userID, sessionID string) (string, time.Time, error) {
    now := time.Now()
    exp := now.Add(s.ttl)
    claims := Claims{
        SessionID: sessionID,
        RegisteredClaims: jwtlib.RegisteredClaims{
            Issuer:    s.issuer,
            Subject:   userID,
            ExpiresAt: jwtlib.NewNumericDate(exp),
            IssuedAt:  jwtlib.NewNumericDate(now),
        },
    }
    token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
    signed, err := token.SignedString(s.secret)
    if err != nil {
        return "", time.Time{}, err
    }
    return signed, exp, nil
}

func (s *Service) ParseClaims(tokenStr string) (*Claims, error) {
    token, err := jwtlib.ParseWithClaims(tokenStr, &Claims{}, func(token *jwtlib.Token) (any, error) {
        return s.secret, nil
    })
    if err != nil {
        return nil, err
    }
    claims, ok := token.Claims.(*Claims)
    if !ok || !token.Valid {
        return nil, ErrInvalidToken
    }
    return claims, nil
}
