package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/qmish/2FA/internal/api/metrics"
	"github.com/qmish/2FA/internal/api/middlewares"
	"github.com/qmish/2FA/internal/auth/service"
	"github.com/qmish/2FA/internal/dto"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/pkg/validator"
)

type AuthHandler struct {
	service service.AuthService
}

func NewAuthHandler(svc service.AuthService) *AuthHandler {
	return &AuthHandler{service: svc}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_input")
		return
	}
	if req.Channel != "" && !isValidAuthChannel(req.Channel) {
		writeError(w, http.StatusBadRequest, "invalid_channel")
		return
	}
	if req.Method != "" && !isValidSecondFactorMethod(req.Method) {
		writeError(w, http.StatusBadRequest, "invalid_method")
		return
	}
	if strings.Contains(req.Username, "@") {
		req.Username = validator.NormalizeEmail(req.Username)
		if !validator.IsEmailValid(req.Username) {
			writeError(w, http.StatusBadRequest, "invalid_email")
			return
		}
	} else if strings.HasPrefix(req.Username, "+") || validator.IsPhoneValid(req.Username) {
		req.Username = validator.NormalizePhone(req.Username)
		if !validator.IsPhoneValid(req.Username) {
			writeError(w, http.StatusBadRequest, "invalid_phone")
			return
		}
	}
	ip := clientIP(r)
	if !validator.IsIPValid(ip) {
		writeError(w, http.StatusBadRequest, "invalid_ip")
		return
	}
	req.IP = ip
	req.UserAgent = r.UserAgent()
	resp, err := h.service.Login(r.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			metrics.Default.IncAuthFailure("login", "invalid_credentials")
			writeError(w, http.StatusUnauthorized, "invalid_credentials")
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			metrics.Default.IncAuthFailure("login", "forbidden")
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		if errors.Is(err, service.ErrRateLimited) {
			metrics.Default.IncAuthFailure("login", "rate_limited")
			writeError(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
		metrics.Default.IncAuthFailure("login", "login_failed")
		writeError(w, http.StatusBadRequest, "login_failed")
		return
	}
	metrics.Default.IncAuthChallenge(string(resp.Method))
	writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req dto.RegisterRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Token = strings.TrimSpace(req.Token)
	if req.Username == "" || req.Password == "" || req.Token == "" {
		writeError(w, http.StatusBadRequest, "invalid_input")
		return
	}
	resp, err := h.service.Register(r.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInviteInvalid):
			metrics.Default.IncAuthRegistration("failed")
			writeError(w, http.StatusForbidden, "invite_invalid")
		case errors.Is(err, service.ErrConflict):
			metrics.Default.IncAuthRegistration("failed")
			writeError(w, http.StatusConflict, "user_conflict")
		case errors.Is(err, service.ErrNotConfigured):
			metrics.Default.IncAuthRegistration("failed")
			writeError(w, http.StatusBadRequest, "invite_not_configured")
		default:
			metrics.Default.IncAuthRegistration("failed")
			writeError(w, http.StatusBadRequest, "register_failed")
		}
		return
	}
	metrics.Default.IncAuthRegistration("success")
	writeJSON(w, http.StatusCreated, resp)
}

func (h *AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req dto.VerifyRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if req.UserID == "" || req.ChallengeID == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "invalid_input")
		return
	}
	if req.Method != "" && !isValidSecondFactorMethod(req.Method) {
		writeError(w, http.StatusBadRequest, "invalid_method")
		return
	}
	ip := clientIP(r)
	if !validator.IsIPValid(ip) {
		writeError(w, http.StatusBadRequest, "invalid_ip")
		return
	}
	req.IP = ip
	req.UserAgent = r.UserAgent()
	resp, err := h.service.VerifySecondFactor(r.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrChallengeNotFound):
			metrics.Default.IncAuthFailure("verify", "challenge_not_found")
			writeError(w, http.StatusNotFound, "challenge_not_found")
		case errors.Is(err, service.ErrChallengeExpired):
			metrics.Default.IncAuthFailure("verify", "challenge_expired")
			writeError(w, http.StatusConflict, "challenge_expired")
		case errors.Is(err, service.ErrSecondFactorFailed):
			metrics.Default.IncAuthFailure("verify", "second_factor_failed")
			writeError(w, http.StatusUnauthorized, "second_factor_failed")
		case errors.Is(err, service.ErrForbidden):
			metrics.Default.IncAuthFailure("verify", "forbidden")
			writeError(w, http.StatusForbidden, "forbidden")
		case errors.Is(err, service.ErrRateLimited):
			metrics.Default.IncAuthFailure("verify", "rate_limited")
			writeError(w, http.StatusTooManyRequests, "rate_limited")
		default:
			metrics.Default.IncAuthFailure("verify", "verify_failed")
			writeError(w, http.StatusBadRequest, "verify_failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req dto.RefreshRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if strings.TrimSpace(req.RefreshToken) == "" {
		writeError(w, http.StatusBadRequest, "invalid_input")
		return
	}
	if !validator.IsIPValid(clientIP(r)) {
		writeError(w, http.StatusBadRequest, "invalid_ip")
		return
	}
	resp, err := h.service.Refresh(r.Context(), req, clientIP(r))
	if err != nil {
		switch {
		case errors.Is(err, service.ErrSessionNotFound):
			writeError(w, http.StatusUnauthorized, "session_not_found")
		case errors.Is(err, service.ErrSessionExpired):
			writeError(w, http.StatusUnauthorized, "session_expired")
		case errors.Is(err, service.ErrForbidden):
			writeError(w, http.StatusForbidden, "forbidden")
		case errors.Is(err, service.ErrRateLimited):
			writeError(w, http.StatusTooManyRequests, "rate_limited")
		default:
			writeError(w, http.StatusBadRequest, "refresh_failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	claims, ok := middlewares.AuthClaimsFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req dto.LogoutRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if req.SessionID == "" {
		req.SessionID = claims.SessionID
	} else if req.SessionID != claims.SessionID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if !validator.IsIPValid(clientIP(r)) {
		writeError(w, http.StatusBadRequest, "invalid_ip")
		return
	}
	if err := h.service.Logout(r.Context(), claims.UserID, req.SessionID, clientIP(r)); err != nil {
		if errors.Is(err, service.ErrForbidden) {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		if errors.Is(err, service.ErrRateLimited) {
			writeError(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
		writeError(w, http.StatusBadRequest, "logout_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) SetupTOTP(w http.ResponseWriter, r *http.Request) {
	claims, ok := middlewares.AuthClaimsFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	resp, err := h.service.SetupTOTP(r.Context(), claims.UserID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrNotFound):
			writeError(w, http.StatusNotFound, "user_not_found")
		case errors.Is(err, service.ErrNotConfigured):
			writeError(w, http.StatusBadRequest, "totp_not_configured")
		default:
			writeError(w, http.StatusBadRequest, "totp_setup_failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) DisableTOTP(w http.ResponseWriter, r *http.Request) {
	claims, ok := middlewares.AuthClaimsFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err := h.service.DisableTOTP(r.Context(), claims.UserID); err != nil {
		switch {
		case errors.Is(err, service.ErrNotFound):
			writeError(w, http.StatusNotFound, "totp_not_found")
		case errors.Is(err, service.ErrNotConfigured):
			writeError(w, http.StatusBadRequest, "totp_not_configured")
		default:
			writeError(w, http.StatusBadRequest, "totp_disable_failed")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) GenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	claims, ok := middlewares.AuthClaimsFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	resp, err := h.service.GenerateRecoveryCodes(r.Context(), claims.UserID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrNotFound):
			writeError(w, http.StatusNotFound, "user_not_found")
		case errors.Is(err, service.ErrNotConfigured):
			writeError(w, http.StatusBadRequest, "recovery_not_configured")
		default:
			writeError(w, http.StatusBadRequest, "recovery_generate_failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) ClearRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	claims, ok := middlewares.AuthClaimsFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err := h.service.ClearRecoveryCodes(r.Context(), claims.UserID); err != nil {
		switch {
		case errors.Is(err, service.ErrNotFound):
			writeError(w, http.StatusNotFound, "user_not_found")
		case errors.Is(err, service.ErrNotConfigured):
			writeError(w, http.StatusBadRequest, "recovery_not_configured")
		default:
			writeError(w, http.StatusBadRequest, "recovery_clear_failed")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) BeginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	resp, err := h.service.BeginPasskeyLogin(r.Context())
	if err != nil {
		switch {
		case errors.Is(err, service.ErrNotConfigured):
			metrics.Default.IncPasskeyEvent("login_begin", "failed")
			writeError(w, http.StatusBadRequest, "passkeys_not_configured")
		default:
			metrics.Default.IncPasskeyEvent("login_begin", "failed")
			writeError(w, http.StatusBadRequest, "passkey_login_begin_failed")
		}
		return
	}
	metrics.Default.IncPasskeyEvent("login_begin", "success")
	writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) FinishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var req dto.PasskeyLoginFinishRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || len(req.Credential) == 0 || strings.TrimSpace(req.SessionID) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	ip := clientIP(r)
	if !validator.IsIPValid(ip) {
		writeError(w, http.StatusBadRequest, "invalid_ip")
		return
	}
	resp, err := h.service.FinishPasskeyLogin(r.Context(), strings.TrimSpace(req.SessionID), req.Credential, ip, r.UserAgent())
	if err != nil {
		switch {
		case errors.Is(err, service.ErrChallengeNotFound):
			metrics.Default.IncPasskeyEvent("login_finish", "failed")
			writeError(w, http.StatusNotFound, "challenge_not_found")
		case errors.Is(err, service.ErrChallengeExpired):
			metrics.Default.IncPasskeyEvent("login_finish", "failed")
			writeError(w, http.StatusConflict, "challenge_expired")
		case errors.Is(err, service.ErrNotConfigured):
			metrics.Default.IncPasskeyEvent("login_finish", "failed")
			writeError(w, http.StatusBadRequest, "passkeys_not_configured")
		default:
			metrics.Default.IncPasskeyEvent("login_finish", "failed")
			writeError(w, http.StatusBadRequest, "passkey_login_failed")
		}
		return
	}
	metrics.Default.IncPasskeyEvent("login_finish", "success")
	writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) BeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	claims, ok := middlewares.AuthClaimsFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	resp, err := h.service.BeginPasskeyRegistration(r.Context(), claims.UserID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrNotFound):
			metrics.Default.IncPasskeyEvent("register_begin", "failed")
			writeError(w, http.StatusNotFound, "user_not_found")
		case errors.Is(err, service.ErrNotConfigured):
			metrics.Default.IncPasskeyEvent("register_begin", "failed")
			writeError(w, http.StatusBadRequest, "passkeys_not_configured")
		default:
			metrics.Default.IncPasskeyEvent("register_begin", "failed")
			writeError(w, http.StatusBadRequest, "passkey_register_begin_failed")
		}
		return
	}
	metrics.Default.IncPasskeyEvent("register_begin", "success")
	writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) FinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	claims, ok := middlewares.AuthClaimsFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req dto.PasskeyRegisterFinishRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || len(req.Credential) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.service.FinishPasskeyRegistration(r.Context(), claims.UserID, req.Credential); err != nil {
		switch {
		case errors.Is(err, service.ErrChallengeNotFound):
			metrics.Default.IncPasskeyEvent("register_finish", "failed")
			writeError(w, http.StatusNotFound, "challenge_not_found")
		case errors.Is(err, service.ErrChallengeExpired):
			metrics.Default.IncPasskeyEvent("register_finish", "failed")
			writeError(w, http.StatusConflict, "challenge_expired")
		case errors.Is(err, service.ErrNotFound):
			metrics.Default.IncPasskeyEvent("register_finish", "failed")
			writeError(w, http.StatusNotFound, "user_not_found")
		case errors.Is(err, service.ErrNotConfigured):
			metrics.Default.IncPasskeyEvent("register_finish", "failed")
			writeError(w, http.StatusBadRequest, "passkeys_not_configured")
		default:
			metrics.Default.IncPasskeyEvent("register_finish", "failed")
			writeError(w, http.StatusBadRequest, "passkey_register_failed")
		}
		return
	}
	metrics.Default.IncPasskeyEvent("register_finish", "success")
	w.WriteHeader(http.StatusNoContent)
}

func isValidSecondFactorMethod(method models.SecondFactorMethod) bool {
	switch method {
	case models.MethodOTP, models.MethodTOTP, models.MethodCall, models.MethodPush, models.MethodRecovery:
		return true
	default:
		return false
	}
}

func isValidAuthChannel(channel models.AuthChannel) bool {
	switch channel {
	case models.ChannelWeb, models.ChannelMobile, models.ChannelVPN, models.ChannelMail, models.ChannelRDP, models.ChannelSSH:
		return true
	default:
		return false
	}
}

func clientIP(r *http.Request) string {
	forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}
