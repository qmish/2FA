package dto

import "github.com/qmish/2FA/internal/models"

type LoginRequest struct {
    Username string             `json:"username"`
    Password string             `json:"password"`
    Channel  models.AuthChannel `json:"channel"`
}

type LoginResponse struct {
    UserID      string                 `json:"user_id"`
    ChallengeID string                 `json:"challenge_id"`
    Method      models.SecondFactorMethod `json:"method"`
}

type VerifyRequest struct {
    UserID      string                 `json:"user_id"`
    ChallengeID string                 `json:"challenge_id"`
    Method      models.SecondFactorMethod `json:"method"`
    Code        string                 `json:"code"`
}

type RefreshRequest struct {
    RefreshToken string `json:"refresh_token"`
}

type TokenPair struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    ExpiresIn    int64  `json:"expires_in"`
}

type LogoutRequest struct {
    SessionID string `json:"session_id"`
}
