package dto

import "github.com/qmish/2FA/internal/models"

type LoginRequest struct {
	Username  string                    `json:"username"`
	Password  string                    `json:"password"`
	Channel   models.AuthChannel        `json:"channel"`
	Method    models.SecondFactorMethod `json:"method"`
	IP        string                    `json:"ip,omitempty"`
	UserAgent string                    `json:"user_agent,omitempty"`
}

type LoginResponse struct {
	UserID      string                    `json:"user_id"`
	ChallengeID string                    `json:"challenge_id"`
	Method      models.SecondFactorMethod `json:"method"`
	ExpiresAt   int64                     `json:"expires_at"`
	Status      models.ChallengeStatus    `json:"status"`
}

type VerifyRequest struct {
	UserID      string                    `json:"user_id"`
	ChallengeID string                    `json:"challenge_id"`
	Method      models.SecondFactorMethod `json:"method"`
	Code        string                    `json:"code"`
	IP          string                    `json:"ip,omitempty"`
	UserAgent   string                    `json:"user_agent,omitempty"`
}

type ChallengeStatusResponse struct {
	ChallengeID string                    `json:"challenge_id"`
	Status      models.ChallengeStatus    `json:"status"`
	Method      models.SecondFactorMethod `json:"method"`
	ExpiresAt   int64                     `json:"expires_at"`
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

type TOTPSetupResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
	Issuer     string `json:"issuer"`
	Digits     int    `json:"digits"`
	Period     int    `json:"period"`
}

type SessionDTO struct {
    ID        string     `json:"id"`
    IP        string     `json:"ip"`
    UserAgent string     `json:"user_agent"`
    CreatedAt int64      `json:"created_at"`
    ExpiresAt int64      `json:"expires_at"`
    LastSeenAt *int64    `json:"last_seen_at,omitempty"`
    RevokedAt *int64     `json:"revoked_at,omitempty"`
}

type SessionListResponse struct {
    Items []SessionDTO `json:"items"`
    Page  PageResponse `json:"page"`
}

type SessionRevokeRequest struct {
    SessionID string `json:"session_id"`
}

type SessionRevokeAllRequest struct {
    ExceptCurrent bool `json:"except_current"`
}

type LockoutStatusResponse struct {
    ID        string `json:"id"`
    UserID    string `json:"user_id"`
    IP        string `json:"ip"`
    Reason    string `json:"reason"`
    ExpiresAt int64  `json:"expires_at"`
}
