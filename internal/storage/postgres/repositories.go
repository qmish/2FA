package postgres

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/internal/repository"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, username, email, phone, status, role, password_hash, ad_dn, created_at, updated_at
        FROM users WHERE id = $1`, id)

	var (
		email, phone, passwordHash, adDN sql.NullString
		status, role                     string
		createdAt, updatedAt             time.Time
		user                             models.User
	)
	if err := row.Scan(
		&user.ID,
		&user.Username,
		&email,
		&phone,
		&status,
		&role,
		&passwordHash,
		&adDN,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, mapNotFound(err)
	}

	user.Email = fromNullString(email)
	user.Phone = fromNullString(phone)
	user.Status = models.UserStatus(status)
	user.Role = models.UserRole(role)
	user.PasswordHash = fromNullString(passwordHash)
	user.AdDN = fromNullString(adDN)
	user.CreatedAt = createdAt
	user.UpdatedAt = updatedAt
	return &user, nil
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, username, email, phone, status, role, password_hash, ad_dn, created_at, updated_at
        FROM users WHERE username = $1`, username)

	var (
		email, phone, passwordHash, adDN sql.NullString
		status, role                     string
		createdAt, updatedAt             time.Time
		user                             models.User
	)
	if err := row.Scan(
		&user.ID,
		&user.Username,
		&email,
		&phone,
		&status,
		&role,
		&passwordHash,
		&adDN,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, mapNotFound(err)
	}
	user.Email = fromNullString(email)
	user.Phone = fromNullString(phone)
	user.Status = models.UserStatus(status)
	user.Role = models.UserRole(role)
	user.PasswordHash = fromNullString(passwordHash)
	user.AdDN = fromNullString(adDN)
	user.CreatedAt = createdAt
	user.UpdatedAt = updatedAt
	return &user, nil
}

func (r *UserRepository) GetByUsernameAndRole(ctx context.Context, username string, role models.UserRole) (*models.User, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, username, email, phone, status, role, password_hash, ad_dn, created_at, updated_at
        FROM users WHERE username = $1 AND role = $2`, username, string(role))

	var (
		email, phone, passwordHash, adDN sql.NullString
		status, roleValue                string
		createdAt, updatedAt             time.Time
		user                             models.User
	)
	if err := row.Scan(
		&user.ID,
		&user.Username,
		&email,
		&phone,
		&status,
		&roleValue,
		&passwordHash,
		&adDN,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, mapNotFound(err)
	}

	user.Email = fromNullString(email)
	user.Phone = fromNullString(phone)
	user.Status = models.UserStatus(status)
	user.Role = models.UserRole(roleValue)
	user.PasswordHash = fromNullString(passwordHash)
	user.AdDN = fromNullString(adDN)
	user.CreatedAt = createdAt
	user.UpdatedAt = updatedAt
	return &user, nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, username, email, phone, status, role, password_hash, ad_dn, created_at, updated_at
        FROM users WHERE email = $1`, email)

	var (
		emailValue, phone, passwordHash, adDN sql.NullString
		status, roleValue                     string
		createdAt, updatedAt                  time.Time
		user                                  models.User
	)
	if err := row.Scan(
		&user.ID,
		&user.Username,
		&emailValue,
		&phone,
		&status,
		&roleValue,
		&passwordHash,
		&adDN,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, mapNotFound(err)
	}
	user.Email = fromNullString(emailValue)
	user.Phone = fromNullString(phone)
	user.Status = models.UserStatus(status)
	user.Role = models.UserRole(roleValue)
	user.PasswordHash = fromNullString(passwordHash)
	user.AdDN = fromNullString(adDN)
	user.CreatedAt = createdAt
	user.UpdatedAt = updatedAt
	return &user, nil
}

func (r *UserRepository) GetByPhone(ctx context.Context, phone string) (*models.User, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, username, email, phone, status, role, password_hash, ad_dn, created_at, updated_at
        FROM users WHERE phone = $1`, phone)

	var (
		emailValue, phoneValue, passwordHash, adDN sql.NullString
		status, roleValue                          string
		createdAt, updatedAt                       time.Time
		user                                       models.User
	)
	if err := row.Scan(
		&user.ID,
		&user.Username,
		&emailValue,
		&phoneValue,
		&status,
		&roleValue,
		&passwordHash,
		&adDN,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, mapNotFound(err)
	}
	user.Email = fromNullString(emailValue)
	user.Phone = fromNullString(phoneValue)
	user.Status = models.UserStatus(status)
	user.Role = models.UserRole(roleValue)
	user.PasswordHash = fromNullString(passwordHash)
	user.AdDN = fromNullString(adDN)
	user.CreatedAt = createdAt
	user.UpdatedAt = updatedAt
	return &user, nil
}

func (r *UserRepository) List(ctx context.Context, filter repository.UserListFilter, limit, offset int) ([]models.User, int, error) {
	base, args := buildUserListQuery(filter)
	countQuery := "SELECT COUNT(*) " + base
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	listQuery := `
        SELECT u.id, u.username, u.email, u.phone, u.status, u.role, u.password_hash, u.ad_dn, u.created_at, u.updated_at
        ` + base + ` ORDER BY u.created_at DESC LIMIT $` + itoa(len(args)-1) + ` OFFSET $` + itoa(len(args))
	rows, err := r.db.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []models.User
	for rows.Next() {
		var (
			email, phone, passwordHash, adDN sql.NullString
			status, role                     string
			createdAt, updatedAt             time.Time
			user                             models.User
		)
		if err := rows.Scan(
			&user.ID,
			&user.Username,
			&email,
			&phone,
			&status,
			&role,
			&passwordHash,
			&adDN,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, 0, err
		}
		user.Email = fromNullString(email)
		user.Phone = fromNullString(phone)
		user.Status = models.UserStatus(status)
		user.Role = models.UserRole(role)
		user.PasswordHash = fromNullString(passwordHash)
		user.AdDN = fromNullString(adDN)
		user.CreatedAt = createdAt
		user.UpdatedAt = updatedAt
		items = append(items, user)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *UserRepository) Create(ctx context.Context, u *models.User) error {
	_, err := r.db.ExecContext(ctx, `
        INSERT INTO users (id, username, email, phone, status, role, password_hash, ad_dn, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		u.ID,
		u.Username,
		nullString(u.Email),
		nullString(u.Phone),
		string(u.Status),
		string(u.Role),
		nullString(u.PasswordHash),
		nullString(u.AdDN),
		u.CreatedAt,
		u.UpdatedAt,
	)
	return err
}

func (r *UserRepository) Update(ctx context.Context, u *models.User) error {
	_, err := r.db.ExecContext(ctx, `
        UPDATE users
        SET email = $2, phone = $3, status = $4, role = $5, password_hash = $6, ad_dn = $7, updated_at = $8
        WHERE id = $1`,
		u.ID,
		nullString(u.Email),
		nullString(u.Phone),
		string(u.Status),
		string(u.Role),
		nullString(u.PasswordHash),
		nullString(u.AdDN),
		u.UpdatedAt,
	)
	return err
}

func (r *UserRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

func (r *UserRepository) SetStatus(ctx context.Context, id string, status models.UserStatus) error {
	_, err := r.db.ExecContext(ctx, `UPDATE users SET status = $2 WHERE id = $1`, id, string(status))
	return err
}

type SessionRepository struct {
	db *sql.DB
}

func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Create(ctx context.Context, s *models.UserSession) error {
	_, err := r.db.ExecContext(ctx, `
        INSERT INTO user_sessions (id, user_id, refresh_token_hash, ip, user_agent, expires_at, created_at, last_seen_at, revoked_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		s.ID,
		s.UserID,
		s.RefreshTokenHash,
		nullString(s.IP),
		nullString(s.UserAgent),
		s.ExpiresAt,
		s.CreatedAt,
		nullTime(s.LastSeenAt),
		nullTime(s.RevokedAt),
	)
	return err
}

func (r *SessionRepository) Revoke(ctx context.Context, id string, revokedAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE user_sessions SET revoked_at = $2 WHERE id = $1`, id, revokedAt)
	return err
}

func (r *SessionRepository) GetByRefreshHash(ctx context.Context, hash string) (*models.UserSession, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, user_id, refresh_token_hash, ip, user_agent, expires_at, created_at, last_seen_at, revoked_at
        FROM user_sessions WHERE refresh_token_hash = $1`, hash)

	var (
		ip, userAgent sql.NullString
		lastSeenAt    sql.NullTime
		revokedAt     sql.NullTime
		s             models.UserSession
	)
	if err := row.Scan(
		&s.ID,
		&s.UserID,
		&s.RefreshTokenHash,
		&ip,
		&userAgent,
		&s.ExpiresAt,
		&s.CreatedAt,
		&lastSeenAt,
		&revokedAt,
	); err != nil {
		return nil, err
	}
	s.IP = fromNullString(ip)
	s.UserAgent = fromNullString(userAgent)
	s.LastSeenAt = fromNullTime(lastSeenAt)
	s.RevokedAt = fromNullTime(revokedAt)
	return &s, nil
}

func (r *SessionRepository) GetByID(ctx context.Context, id string) (*models.UserSession, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, user_id, refresh_token_hash, ip, user_agent, expires_at, created_at, last_seen_at, revoked_at
        FROM user_sessions WHERE id = $1`, id)
	var (
		ip, userAgent sql.NullString
		lastSeenAt    sql.NullTime
		revokedAt     sql.NullTime
		s             models.UserSession
	)
	if err := row.Scan(
		&s.ID,
		&s.UserID,
		&s.RefreshTokenHash,
		&ip,
		&userAgent,
		&s.ExpiresAt,
		&s.CreatedAt,
		&lastSeenAt,
		&revokedAt,
	); err != nil {
		return nil, mapNotFound(err)
	}
	s.IP = fromNullString(ip)
	s.UserAgent = fromNullString(userAgent)
	s.LastSeenAt = fromNullTime(lastSeenAt)
	s.RevokedAt = fromNullTime(revokedAt)
	return &s, nil
}

func (r *SessionRepository) RotateRefreshHash(ctx context.Context, id string, newHash string) error {
	_, err := r.db.ExecContext(ctx, `
        UPDATE user_sessions SET refresh_token_hash = $2 WHERE id = $1`, id, newHash)
	return err
}

func (r *SessionRepository) List(ctx context.Context, filter repository.SessionListFilter, limit, offset int) ([]models.UserSession, int, error) {
	where := []string{}
	args := []any{}
	if filter.UserID != "" {
		where = append(where, "user_id = $"+itoa(len(args)+1))
		args = append(args, filter.UserID)
	}
	if filter.IP != "" {
		where = append(where, "ip = $"+itoa(len(args)+1))
		args = append(args, filter.IP)
	}
	if filter.UserAgent != "" {
		where = append(where, "user_agent = $"+itoa(len(args)+1))
		args = append(args, filter.UserAgent)
	}
	if filter.ActiveOnly {
		where = append(where, "revoked_at IS NULL")
	}
	base := "FROM user_sessions"
	if len(where) > 0 {
		base += " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) "+base, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := r.db.QueryContext(ctx, `
        SELECT id, user_id, refresh_token_hash, ip, user_agent, expires_at, created_at, last_seen_at, revoked_at
        `+base+` ORDER BY created_at DESC LIMIT $`+itoa(len(args)-1)+` OFFSET $`+itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []models.UserSession
	for rows.Next() {
		var (
			ip, userAgent sql.NullString
			lastSeenAt    sql.NullTime
			revokedAt     sql.NullTime
			s             models.UserSession
		)
		if err := rows.Scan(
			&s.ID,
			&s.UserID,
			&s.RefreshTokenHash,
			&ip,
			&userAgent,
			&s.ExpiresAt,
			&s.CreatedAt,
			&lastSeenAt,
			&revokedAt,
		); err != nil {
			return nil, 0, err
		}
		s.IP = fromNullString(ip)
		s.UserAgent = fromNullString(userAgent)
		s.LastSeenAt = fromNullTime(lastSeenAt)
		s.RevokedAt = fromNullTime(revokedAt)
		items = append(items, s)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *SessionRepository) RevokeAllByUser(ctx context.Context, userID string, exceptSessionID string, revokedAt time.Time) error {
	if exceptSessionID == "" {
		_, err := r.db.ExecContext(ctx, `
            UPDATE user_sessions SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`, userID, revokedAt)
		return err
	}
	_, err := r.db.ExecContext(ctx, `
        UPDATE user_sessions SET revoked_at = $3 WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL`,
		userID, exceptSessionID, revokedAt)
	return err
}

func (r *SessionRepository) Touch(ctx context.Context, id string, seenAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `
        UPDATE user_sessions SET last_seen_at = $2 WHERE id = $1`, id, seenAt)
	return err
}

type ChallengeRepository struct {
	db *sql.DB
}

func NewChallengeRepository(db *sql.DB) *ChallengeRepository {
	return &ChallengeRepository{db: db}
}

func (r *ChallengeRepository) GetByID(ctx context.Context, id string) (*models.Challenge, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, user_id, method, status, code_hash, provider_id, expires_at, created_at, updated_at
        FROM challenges WHERE id = $1`, id)
	var (
		method, status     string
		codeHash, provider sql.NullString
		c                  models.Challenge
	)
	if err := row.Scan(
		&c.ID,
		&c.UserID,
		&method,
		&status,
		&codeHash,
		&provider,
		&c.ExpiresAt,
		&c.CreatedAt,
		&c.UpdatedAt,
	); err != nil {
		return nil, mapNotFound(err)
	}
	c.Method = models.SecondFactorMethod(method)
	c.Status = models.ChallengeStatus(status)
	c.CodeHash = fromNullString(codeHash)
	c.ProviderID = fromNullString(provider)
	return &c, nil
}

func (r *ChallengeRepository) GetActiveByUserAndMethod(ctx context.Context, userID string, method models.SecondFactorMethod) (*models.Challenge, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, user_id, method, status, code_hash, provider_id, expires_at, created_at, updated_at
        FROM challenges
        WHERE user_id = $1 AND method = $2 AND status IN ('created','sent','pending')
        ORDER BY created_at DESC
        LIMIT 1`, userID, string(method))
	var (
		methodValue, status string
		codeHash, provider  sql.NullString
		c                   models.Challenge
	)
	if err := row.Scan(
		&c.ID,
		&c.UserID,
		&methodValue,
		&status,
		&codeHash,
		&provider,
		&c.ExpiresAt,
		&c.CreatedAt,
		&c.UpdatedAt,
	); err != nil {
		return nil, mapNotFound(err)
	}
	c.Method = models.SecondFactorMethod(methodValue)
	c.Status = models.ChallengeStatus(status)
	c.CodeHash = fromNullString(codeHash)
	c.ProviderID = fromNullString(provider)
	return &c, nil
}

func (r *ChallengeRepository) Create(ctx context.Context, c *models.Challenge) error {
	_, err := r.db.ExecContext(ctx, `
        INSERT INTO challenges (id, user_id, method, status, code_hash, provider_id, expires_at, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		c.ID,
		c.UserID,
		string(c.Method),
		string(c.Status),
		nullString(c.CodeHash),
		nullString(c.ProviderID),
		c.ExpiresAt,
		c.CreatedAt,
		c.UpdatedAt,
	)
	return err
}

func (r *ChallengeRepository) UpdateStatus(ctx context.Context, id string, status models.ChallengeStatus) error {
	_, err := r.db.ExecContext(ctx, `
        UPDATE challenges SET status = $2, updated_at = now() WHERE id = $1`, id, string(status))
	return err
}

func (r *ChallengeRepository) UpdateDelivery(ctx context.Context, id string, providerID string, status models.ChallengeStatus) error {
	_, err := r.db.ExecContext(ctx, `
        UPDATE challenges SET provider_id = $2, status = $3, updated_at = now() WHERE id = $1`,
		id,
		nullString(providerID),
		string(status),
	)
	return err
}

func (r *ChallengeRepository) MarkExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
        UPDATE challenges SET status = 'expired', updated_at = now()
        WHERE status IN ('created','sent','pending') AND expires_at < $1`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

type OTPSecretRepository struct {
	db *sql.DB
}

func NewOTPSecretRepository(db *sql.DB) *OTPSecretRepository {
	return &OTPSecretRepository{db: db}
}

func (r *OTPSecretRepository) GetActiveByUser(ctx context.Context, userID string) (*models.OTPSecret, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, user_id, secret, issuer, digits, period, enabled, created_at
        FROM otp_secrets WHERE user_id = $1 AND enabled = true
        ORDER BY created_at DESC LIMIT 1`, userID)
	var issuer sql.NullString
	var item models.OTPSecret
	if err := row.Scan(&item.ID, &item.UserID, &item.Secret, &issuer, &item.Digits, &item.Period, &item.Enabled, &item.CreatedAt); err != nil {
		return nil, mapNotFound(err)
	}
	item.Issuer = fromNullString(issuer)
	return &item, nil
}

func (r *OTPSecretRepository) Create(ctx context.Context, s *models.OTPSecret) error {
	_, err := r.db.ExecContext(ctx, `
        INSERT INTO otp_secrets (id, user_id, secret, issuer, digits, period, enabled, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		s.ID, s.UserID, s.Secret, nullString(s.Issuer), s.Digits, s.Period, s.Enabled, s.CreatedAt)
	return err
}

func (r *OTPSecretRepository) Disable(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE otp_secrets SET enabled = false WHERE id = $1`, id)
	return err
}

type InviteRepository struct {
	db *sql.DB
}

func NewInviteRepository(db *sql.DB) *InviteRepository {
	return &InviteRepository{db: db}
}

func (r *InviteRepository) Create(ctx context.Context, invite *models.Invite) error {
	_, err := r.db.ExecContext(ctx, `
        INSERT INTO invites (id, token_hash, email, phone, role, status, expires_at, created_at, used_at, used_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		invite.ID,
		invite.TokenHash,
		nullString(invite.Email),
		nullString(invite.Phone),
		string(invite.Role),
		string(invite.Status),
		invite.ExpiresAt,
		invite.CreatedAt,
		nullTime(invite.UsedAt),
		nullString(invite.UsedBy),
	)
	return err
}

func (r *InviteRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*models.Invite, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, token_hash, email, phone, role, status, expires_at, created_at, used_at, used_by
        FROM invites WHERE token_hash = $1`, tokenHash)
	var (
		email, phone, usedBy sql.NullString
		status, role         string
		usedAt               sql.NullTime
		item                 models.Invite
	)
	if err := row.Scan(
		&item.ID,
		&item.TokenHash,
		&email,
		&phone,
		&role,
		&status,
		&item.ExpiresAt,
		&item.CreatedAt,
		&usedAt,
		&usedBy,
	); err != nil {
		return nil, mapNotFound(err)
	}
	item.Email = fromNullString(email)
	item.Phone = fromNullString(phone)
	item.Role = models.UserRole(role)
	item.Status = models.InviteStatus(status)
	item.UsedBy = fromNullString(usedBy)
	if usedAt.Valid {
		item.UsedAt = &usedAt.Time
	}
	return &item, nil
}

func (r *InviteRepository) MarkUsed(ctx context.Context, id string, userID string, usedAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `
        UPDATE invites SET status = 'used', used_at = $2, used_by = $3 WHERE id = $1`,
		id, usedAt, nullString(userID))
	return err
}

func (r *InviteRepository) MarkExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
        UPDATE invites SET status = 'expired' WHERE status = 'pending' AND expires_at < $1`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

type DeviceRepository struct {
	db *sql.DB
}

func NewDeviceRepository(db *sql.DB) *DeviceRepository {
	return &DeviceRepository{db: db}
}

func (r *DeviceRepository) ListByUser(ctx context.Context, userID string) ([]models.Device, error) {
	rows, err := r.db.QueryContext(ctx, `
        SELECT id, user_id, type, name, status, last_seen_at, created_at
        FROM devices WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []models.Device
	for rows.Next() {
		var (
			name     sql.NullString
			status   string
			lastSeen sql.NullTime
			device   models.Device
		)
		if err := rows.Scan(
			&device.ID,
			&device.UserID,
			&device.Type,
			&name,
			&status,
			&lastSeen,
			&device.CreatedAt,
		); err != nil {
			return nil, err
		}
		device.Name = fromNullString(name)
		device.Status = models.DeviceStatus(status)
		device.LastSeenAt = fromNullTime(lastSeen)
		items = append(items, device)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (r *DeviceRepository) Upsert(ctx context.Context, d *models.Device) error {
	_, err := r.db.ExecContext(ctx, `
        INSERT INTO devices (id, user_id, type, name, status, last_seen_at, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (id) DO UPDATE SET
          name = EXCLUDED.name,
          status = EXCLUDED.status,
          last_seen_at = EXCLUDED.last_seen_at`,
		d.ID,
		d.UserID,
		d.Type,
		nullString(d.Name),
		string(d.Status),
		nullTime(d.LastSeenAt),
		d.CreatedAt,
	)
	return err
}

func (r *DeviceRepository) Disable(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE devices SET status = $2 WHERE id = $1`, id, string(models.DeviceDisabled))
	return err
}

type PolicyRepository struct {
	db *sql.DB
}

func NewPolicyRepository(db *sql.DB) *PolicyRepository {
	return &PolicyRepository{db: db}
}

func (r *PolicyRepository) GetByID(ctx context.Context, id string) (*models.Policy, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, name, priority, status, created_at
        FROM policies WHERE id = $1`, id)
	var status string
	var p models.Policy
	if err := row.Scan(&p.ID, &p.Name, &p.Priority, &status, &p.CreatedAt); err != nil {
		return nil, mapNotFound(err)
	}
	p.Status = models.PolicyStatus(status)
	return &p, nil
}

func (r *PolicyRepository) GetByName(ctx context.Context, name string) (*models.Policy, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, name, priority, status, created_at
        FROM policies WHERE name = $1`, name)
	var status string
	var p models.Policy
	if err := row.Scan(&p.ID, &p.Name, &p.Priority, &status, &p.CreatedAt); err != nil {
		return nil, mapNotFound(err)
	}
	p.Status = models.PolicyStatus(status)
	return &p, nil
}

func (r *PolicyRepository) List(ctx context.Context, limit, offset int) ([]models.Policy, int, error) {
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM policies`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx, `
        SELECT id, name, priority, status, created_at
        FROM policies ORDER BY priority ASC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []models.Policy
	for rows.Next() {
		var status string
		var p models.Policy
		if err := rows.Scan(&p.ID, &p.Name, &p.Priority, &status, &p.CreatedAt); err != nil {
			return nil, 0, err
		}
		p.Status = models.PolicyStatus(status)
		items = append(items, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *PolicyRepository) Create(ctx context.Context, p *models.Policy) error {
	_, err := r.db.ExecContext(ctx, `
        INSERT INTO policies (id, name, priority, status, created_at)
        VALUES ($1,$2,$3,$4,$5)`,
		p.ID, p.Name, p.Priority, string(p.Status), p.CreatedAt)
	return err
}

func (r *PolicyRepository) Update(ctx context.Context, p *models.Policy) error {
	_, err := r.db.ExecContext(ctx, `
        UPDATE policies SET name = $2, priority = $3, status = $4 WHERE id = $1`,
		p.ID, p.Name, p.Priority, string(p.Status))
	return err
}

func (r *PolicyRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM policies WHERE id = $1`, id)
	return err
}

func (r *PolicyRepository) SetStatus(ctx context.Context, id string, status models.PolicyStatus) error {
	_, err := r.db.ExecContext(ctx, `UPDATE policies SET status = $2 WHERE id = $1`, id, string(status))
	return err
}

type PolicyRuleRepository struct {
	db *sql.DB
}

func NewPolicyRuleRepository(db *sql.DB) *PolicyRuleRepository {
	return &PolicyRuleRepository{db: db}
}

func (r *PolicyRuleRepository) ListByPolicy(ctx context.Context, policyID string) ([]models.PolicyRule, error) {
	rows, err := r.db.QueryContext(ctx, `
        SELECT id, policy_id, rule_type, rule_value, created_at
        FROM policy_rules WHERE policy_id = $1`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []models.PolicyRule
	for rows.Next() {
		var ruleType string
		var rule models.PolicyRule
		if err := rows.Scan(&rule.ID, &rule.PolicyID, &ruleType, &rule.RuleValue, &rule.CreatedAt); err != nil {
			return nil, err
		}
		rule.RuleType = models.PolicyRuleType(ruleType)
		items = append(items, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (r *PolicyRuleRepository) Create(ctx context.Context, rule *models.PolicyRule) error {
	_, err := r.db.ExecContext(ctx, `
        INSERT INTO policy_rules (id, policy_id, rule_type, rule_value, created_at)
        VALUES ($1,$2,$3,$4,$5)`,
		rule.ID, rule.PolicyID, string(rule.RuleType), rule.RuleValue, rule.CreatedAt)
	return err
}

func (r *PolicyRuleRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM policy_rules WHERE id = $1`, id)
	return err
}

func (r *PolicyRuleRepository) DeleteByPolicy(ctx context.Context, policyID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM policy_rules WHERE policy_id = $1`, policyID)
	return err
}

type RadiusClientRepository struct {
	db *sql.DB
}

func NewRadiusClientRepository(db *sql.DB) *RadiusClientRepository {
	return &RadiusClientRepository{db: db}
}

func (r *RadiusClientRepository) GetByID(ctx context.Context, id string) (*models.RadiusClient, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, name, ip, secret, enabled, created_at
        FROM radius_clients WHERE id = $1`, id)
	var c models.RadiusClient
	if err := row.Scan(&c.ID, &c.Name, &c.IP, &c.Secret, &c.Enabled, &c.CreatedAt); err != nil {
		return nil, mapNotFound(err)
	}
	return &c, nil
}

func (r *RadiusClientRepository) GetByIP(ctx context.Context, ip string) (*models.RadiusClient, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, name, ip, secret, enabled, created_at
        FROM radius_clients WHERE ip = $1`, ip)
	var c models.RadiusClient
	if err := row.Scan(&c.ID, &c.Name, &c.IP, &c.Secret, &c.Enabled, &c.CreatedAt); err != nil {
		return nil, mapNotFound(err)
	}
	return &c, nil
}

func (r *RadiusClientRepository) List(ctx context.Context, limit, offset int) ([]models.RadiusClient, int, error) {
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM radius_clients`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx, `
        SELECT id, name, ip, secret, enabled, created_at
        FROM radius_clients ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []models.RadiusClient
	for rows.Next() {
		var c models.RadiusClient
		if err := rows.Scan(&c.ID, &c.Name, &c.IP, &c.Secret, &c.Enabled, &c.CreatedAt); err != nil {
			return nil, 0, err
		}
		items = append(items, c)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *RadiusClientRepository) Create(ctx context.Context, c *models.RadiusClient) error {
	_, err := r.db.ExecContext(ctx, `
        INSERT INTO radius_clients (id, name, ip, secret, enabled, created_at)
        VALUES ($1,$2,$3,$4,$5,$6)`,
		c.ID, c.Name, c.IP, c.Secret, c.Enabled, c.CreatedAt)
	return err
}

func (r *RadiusClientRepository) Update(ctx context.Context, c *models.RadiusClient) error {
	_, err := r.db.ExecContext(ctx, `
        UPDATE radius_clients SET name = $2, secret = $3, enabled = $4 WHERE id = $1`,
		c.ID, c.Name, c.Secret, c.Enabled)
	return err
}

func (r *RadiusClientRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM radius_clients WHERE id = $1`, id)
	return err
}

func (r *RadiusClientRepository) SetEnabled(ctx context.Context, id string, enabled bool) error {
	_, err := r.db.ExecContext(ctx, `UPDATE radius_clients SET enabled = $2 WHERE id = $1`, id, enabled)
	return err
}

type AuditRepository struct {
	db *sql.DB
}

func NewAuditRepository(db *sql.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

func (r *AuditRepository) Create(ctx context.Context, e *models.AuditEvent) error {
	_, err := r.db.ExecContext(ctx, `
        INSERT INTO audit_events (id, actor_user_id, action, entity_type, entity_id, payload, ip, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		e.ID,
		nullString(e.ActorUserID),
		string(e.Action),
		string(e.EntityType),
		nullString(e.EntityID),
		nullString(e.Payload),
		nullString(e.IP),
		e.CreatedAt,
	)
	return err
}

func (r *AuditRepository) List(ctx context.Context, filter repository.AuditFilter, limit, offset int) ([]models.AuditEvent, int, error) {
	where := []string{}
	args := []any{}
	if filter.ActorUserID != "" {
		where = append(where, "actor_user_id = $"+itoa(len(args)+1))
		args = append(args, filter.ActorUserID)
	}
	if filter.EntityType != "" {
		where = append(where, "entity_type = $"+itoa(len(args)+1))
		args = append(args, string(filter.EntityType))
	}
	if filter.Action != "" {
		where = append(where, "action = $"+itoa(len(args)+1))
		args = append(args, string(filter.Action))
	}
	if filter.EntityID != "" {
		where = append(where, "entity_id = $"+itoa(len(args)+1))
		args = append(args, filter.EntityID)
	}
	if filter.IP != "" {
		where = append(where, "ip = $"+itoa(len(args)+1))
		args = append(args, filter.IP)
	}
	if filter.Payload != "" {
		where = append(where, "payload = $"+itoa(len(args)+1))
		args = append(args, filter.Payload)
	}
	if !filter.From.IsZero() {
		where = append(where, "created_at >= $"+itoa(len(args)+1))
		args = append(args, filter.From)
	}
	if !filter.To.IsZero() {
		where = append(where, "created_at <= $"+itoa(len(args)+1))
		args = append(args, filter.To)
	}
	base := "FROM audit_events"
	if len(where) > 0 {
		base += " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) "+base, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := r.db.QueryContext(ctx, `
        SELECT id, actor_user_id, action, entity_type, entity_id, payload, ip, created_at
        `+base+` ORDER BY created_at DESC LIMIT $`+itoa(len(args)-1)+` OFFSET $`+itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []models.AuditEvent
	for rows.Next() {
		var (
			actorID, entityID, payload, ip sql.NullString
			action, entityType             string
			e                              models.AuditEvent
		)
		if err := rows.Scan(&e.ID, &actorID, &action, &entityType, &entityID, &payload, &ip, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		e.ActorUserID = fromNullString(actorID)
		e.Action = models.AuditAction(action)
		e.EntityType = models.AuditEntityType(entityType)
		e.EntityID = fromNullString(entityID)
		e.Payload = fromNullString(payload)
		e.IP = fromNullString(ip)
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

type LoginHistoryRepository struct {
	db *sql.DB
}

func NewLoginHistoryRepository(db *sql.DB) *LoginHistoryRepository {
	return &LoginHistoryRepository{db: db}
}

func (r *LoginHistoryRepository) Create(ctx context.Context, h *models.LoginHistory) error {
	_, err := r.db.ExecContext(ctx, `
        INSERT INTO login_history (id, user_id, channel, result, ip, device_id, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		h.ID,
		nullString(h.UserID),
		string(h.Channel),
		string(h.Result),
		nullString(h.IP),
		nullString(h.DeviceID),
		h.CreatedAt,
	)
	return err
}

func (r *LoginHistoryRepository) List(ctx context.Context, filter repository.LoginHistoryFilter, limit, offset int) ([]models.LoginHistory, int, error) {
	where := []string{}
	args := []any{}
	if filter.UserID != "" {
		where = append(where, "user_id = $"+itoa(len(args)+1))
		args = append(args, filter.UserID)
	}
	if filter.Channel != "" {
		where = append(where, "channel = $"+itoa(len(args)+1))
		args = append(args, string(filter.Channel))
	}
	if filter.Result != "" {
		where = append(where, "result = $"+itoa(len(args)+1))
		args = append(args, string(filter.Result))
	}
	if filter.IP != "" {
		where = append(where, "ip = $"+itoa(len(args)+1))
		args = append(args, filter.IP)
	}
	if filter.DeviceID != "" {
		where = append(where, "device_id = $"+itoa(len(args)+1))
		args = append(args, filter.DeviceID)
	}
	if !filter.From.IsZero() {
		where = append(where, "created_at >= $"+itoa(len(args)+1))
		args = append(args, filter.From)
	}
	if !filter.To.IsZero() {
		where = append(where, "created_at <= $"+itoa(len(args)+1))
		args = append(args, filter.To)
	}
	base := "FROM login_history"
	if len(where) > 0 {
		base += " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) "+base, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := r.db.QueryContext(ctx, `
        SELECT id, user_id, channel, result, ip, device_id, created_at
        `+base+` ORDER BY created_at DESC LIMIT $`+itoa(len(args)-1)+` OFFSET $`+itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []models.LoginHistory
	for rows.Next() {
		var (
			userIDValue, ip, deviceID sql.NullString
			channelValue, result      string
			h                         models.LoginHistory
		)
		if err := rows.Scan(&h.ID, &userIDValue, &channelValue, &result, &ip, &deviceID, &h.CreatedAt); err != nil {
			return nil, 0, err
		}
		h.UserID = fromNullString(userIDValue)
		h.Channel = models.AuthChannel(channelValue)
		h.Result = models.AuthResult(result)
		h.IP = fromNullString(ip)
		h.DeviceID = fromNullString(deviceID)
		items = append(items, h)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *LoginHistoryRepository) CountFailures(ctx context.Context, userID string, since time.Time) (int, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT COUNT(*) FROM login_history
        WHERE user_id = $1 AND result = $2 AND created_at >= $3`,
		userID,
		string(models.AuthDeny),
		since,
	)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

type LockoutRepository struct {
	db *sql.DB
}

func NewLockoutRepository(db *sql.DB) *LockoutRepository {
	return &LockoutRepository{db: db}
}

func (r *LockoutRepository) Create(ctx context.Context, l *models.Lockout) error {
	_, err := r.db.ExecContext(ctx, `
        INSERT INTO lockouts (id, user_id, ip, reason, expires_at, created_at)
        VALUES ($1,$2,$3,$4,$5,$6)`,
		l.ID,
		nullString(l.UserID),
		l.IP,
		l.Reason,
		l.ExpiresAt,
		l.CreatedAt,
	)
	return err
}

func (r *LockoutRepository) GetActive(ctx context.Context, userID string, ip string, now time.Time) (*models.Lockout, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, user_id, ip, reason, expires_at, created_at
        FROM lockouts
        WHERE expires_at > $3 AND (user_id = $1 OR ip = $2)
        ORDER BY expires_at DESC
        LIMIT 1`, userID, ip, now)
	var (
		userIDValue sql.NullString
		lockout     models.Lockout
	)
	if err := row.Scan(
		&lockout.ID,
		&userIDValue,
		&lockout.IP,
		&lockout.Reason,
		&lockout.ExpiresAt,
		&lockout.CreatedAt,
	); err != nil {
		return nil, mapNotFound(err)
	}
	lockout.UserID = fromNullString(userIDValue)
	return &lockout, nil
}

func (r *LockoutRepository) ClearExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM lockouts WHERE expires_at < $1`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r *LockoutRepository) List(ctx context.Context, filter repository.LockoutFilter, limit, offset int) ([]models.Lockout, int, error) {
	where := []string{}
	args := []any{}
	if filter.UserID != "" {
		where = append(where, "user_id = $"+itoa(len(args)+1))
		args = append(args, filter.UserID)
	}
	if filter.IP != "" {
		where = append(where, "ip = $"+itoa(len(args)+1))
		args = append(args, filter.IP)
	}
	if filter.Reason != "" {
		where = append(where, "reason = $"+itoa(len(args)+1))
		args = append(args, filter.Reason)
	}
	if filter.ActiveOnly {
		where = append(where, "expires_at > $"+itoa(len(args)+1))
		args = append(args, filter.Now)
	}
	base := "FROM lockouts"
	if len(where) > 0 {
		base += " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) "+base, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := r.db.QueryContext(ctx, `
        SELECT id, user_id, ip, reason, expires_at, created_at
        `+base+` ORDER BY created_at DESC LIMIT $`+itoa(len(args)-1)+` OFFSET $`+itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []models.Lockout
	for rows.Next() {
		var (
			userIDValue sql.NullString
			l           models.Lockout
		)
		if err := rows.Scan(
			&l.ID,
			&userIDValue,
			&l.IP,
			&l.Reason,
			&l.ExpiresAt,
			&l.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		l.UserID = fromNullString(userIDValue)
		items = append(items, l)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *LockoutRepository) ClearByFilter(ctx context.Context, filter repository.LockoutFilter) error {
	where := []string{}
	args := []any{}
	if filter.UserID != "" {
		where = append(where, "user_id = $"+itoa(len(args)+1))
		args = append(args, filter.UserID)
	}
	if filter.IP != "" {
		where = append(where, "ip = $"+itoa(len(args)+1))
		args = append(args, filter.IP)
	}
	if filter.Reason != "" {
		where = append(where, "reason = $"+itoa(len(args)+1))
		args = append(args, filter.Reason)
	}
	if filter.ActiveOnly {
		where = append(where, "expires_at > $"+itoa(len(args)+1))
		args = append(args, filter.Now)
	}
	query := "DELETE FROM lockouts"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	_, err := r.db.ExecContext(ctx, query, args...)
	return err
}

type RadiusRequestRepository struct {
	db *sql.DB
}

func NewRadiusRequestRepository(db *sql.DB) *RadiusRequestRepository {
	return &RadiusRequestRepository{db: db}
}

func (r *RadiusRequestRepository) Create(ctx context.Context, req *models.RadiusRequest) error {
	_, err := r.db.ExecContext(ctx, `
        INSERT INTO radius_requests (id, client_id, username, nas_ip, result, request_id, request_attrs, response_attrs, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		req.ID,
		nullString(req.ClientID),
		nullString(req.Username),
		nullString(req.NASIP),
		string(req.Result),
		nullString(req.RequestID),
		nullString(req.RequestAttrs),
		nullString(req.ResponseAttrs),
		req.CreatedAt,
	)
	return err
}

func (r *RadiusRequestRepository) List(ctx context.Context, filter repository.RadiusRequestFilter, limit, offset int) ([]models.RadiusRequest, int, error) {
	where := []string{}
	args := []any{}
	if filter.ClientID != "" {
		where = append(where, "client_id = $"+itoa(len(args)+1))
		args = append(args, filter.ClientID)
	}
	if filter.Username != "" {
		where = append(where, "username = $"+itoa(len(args)+1))
		args = append(args, filter.Username)
	}
	if filter.Result != "" {
		where = append(where, "result = $"+itoa(len(args)+1))
		args = append(args, string(filter.Result))
	}
	if !filter.From.IsZero() {
		where = append(where, "created_at >= $"+itoa(len(args)+1))
		args = append(args, filter.From)
	}
	if !filter.To.IsZero() {
		where = append(where, "created_at <= $"+itoa(len(args)+1))
		args = append(args, filter.To)
	}
	base := "FROM radius_requests"
	if len(where) > 0 {
		base += " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) "+base, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := r.db.QueryContext(ctx, `
        SELECT id, client_id, username, nas_ip, result, request_id, request_attrs, response_attrs, created_at
        `+base+` ORDER BY created_at DESC LIMIT $`+itoa(len(args)-1)+` OFFSET $`+itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []models.RadiusRequest
	for rows.Next() {
		var (
			clientIDValue, usernameValue, nasIP, requestID, requestAttrs, responseAttrs sql.NullString
			resultValue                                                                 string
			req                                                                         models.RadiusRequest
		)
		if err := rows.Scan(&req.ID, &clientIDValue, &usernameValue, &nasIP, &resultValue, &requestID, &requestAttrs, &responseAttrs, &req.CreatedAt); err != nil {
			return nil, 0, err
		}
		req.ClientID = fromNullString(clientIDValue)
		req.Username = fromNullString(usernameValue)
		req.NASIP = fromNullString(nasIP)
		req.Result = models.RadiusResult(resultValue)
		req.RequestID = fromNullString(requestID)
		req.RequestAttrs = fromNullString(requestAttrs)
		req.ResponseAttrs = fromNullString(responseAttrs)
		items = append(items, req)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *RadiusRequestRepository) UpdateResult(ctx context.Context, id string, result models.RadiusResult) error {
	_, err := r.db.ExecContext(ctx, `UPDATE radius_requests SET result = $2 WHERE id = $1`, id, string(result))
	return err
}

type RolePermissionRepository struct {
	db *sql.DB
}

func NewRolePermissionRepository(db *sql.DB) *RolePermissionRepository {
	return &RolePermissionRepository{db: db}
}

func (r *RolePermissionRepository) ListByRole(ctx context.Context, role models.UserRole) ([]models.Permission, error) {
	rows, err := r.db.QueryContext(ctx, `
        SELECT permission FROM role_permissions WHERE role = $1`, string(role))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []models.Permission
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		perms = append(perms, models.Permission(p))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return perms, nil
}

func (r *RolePermissionRepository) SetRolePermissions(ctx context.Context, role models.UserRole, perms []models.Permission) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM role_permissions WHERE role = $1`, string(role)); err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, perm := range perms {
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO role_permissions (role, permission) VALUES ($1,$2)`, string(role), string(perm)); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

type GroupRepository struct {
	db *sql.DB
}

func NewGroupRepository(db *sql.DB) *GroupRepository {
	return &GroupRepository{db: db}
}

func (r *GroupRepository) GetByID(ctx context.Context, id string) (*models.Group, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, name, description, created_at
        FROM groups WHERE id = $1`, id)
	var g models.Group
	var desc sql.NullString
	if err := row.Scan(&g.ID, &g.Name, &desc, &g.CreatedAt); err != nil {
		return nil, mapNotFound(err)
	}
	g.Description = fromNullString(desc)
	return &g, nil
}

func (r *GroupRepository) GetByName(ctx context.Context, name string) (*models.Group, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT id, name, description, created_at
        FROM groups WHERE name = $1`, name)
	var g models.Group
	var desc sql.NullString
	if err := row.Scan(&g.ID, &g.Name, &desc, &g.CreatedAt); err != nil {
		return nil, mapNotFound(err)
	}
	g.Description = fromNullString(desc)
	return &g, nil
}

func (r *GroupRepository) List(ctx context.Context, limit, offset int) ([]models.Group, int, error) {
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM groups`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx, `
        SELECT id, name, description, created_at
        FROM groups ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []models.Group
	for rows.Next() {
		var g models.Group
		var desc sql.NullString
		if err := rows.Scan(&g.ID, &g.Name, &desc, &g.CreatedAt); err != nil {
			return nil, 0, err
		}
		g.Description = fromNullString(desc)
		items = append(items, g)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *GroupRepository) Create(ctx context.Context, g *models.Group) error {
	_, err := r.db.ExecContext(ctx, `
        INSERT INTO groups (id, name, description, created_at)
        VALUES ($1,$2,$3,$4)`, g.ID, g.Name, nullString(g.Description), g.CreatedAt)
	return err
}

func (r *GroupRepository) Update(ctx context.Context, g *models.Group) error {
	_, err := r.db.ExecContext(ctx, `
        UPDATE groups SET name = $2, description = $3 WHERE id = $1`,
		g.ID, g.Name, nullString(g.Description))
	return err
}

func (r *GroupRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM groups WHERE id = $1`, id)
	return err
}

type UserGroupRepository struct {
	db *sql.DB
}

func NewUserGroupRepository(db *sql.DB) *UserGroupRepository {
	return &UserGroupRepository{db: db}
}

func (r *UserGroupRepository) AddUser(ctx context.Context, groupID, userID string) error {
	_, err := r.db.ExecContext(ctx, `
        INSERT INTO user_groups (user_id, group_id, created_at)
        VALUES ($1,$2,now())`, userID, groupID)
	return err
}

func (r *UserGroupRepository) RemoveUser(ctx context.Context, groupID, userID string) error {
	_, err := r.db.ExecContext(ctx, `
        DELETE FROM user_groups WHERE group_id = $1 AND user_id = $2`, groupID, userID)
	return err
}

func (r *UserGroupRepository) ListUsers(ctx context.Context, groupID string, limit, offset int) ([]models.User, int, error) {
	var total int
	if err := r.db.QueryRowContext(ctx, `
        SELECT COUNT(*) FROM user_groups WHERE group_id = $1`, groupID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx, `
        SELECT u.id, u.username, u.email, u.phone, u.status, u.role, u.password_hash, u.ad_dn, u.created_at, u.updated_at
        FROM user_groups ug
        JOIN users u ON u.id = ug.user_id
        WHERE ug.group_id = $1
        ORDER BY u.created_at DESC
        LIMIT $2 OFFSET $3`, groupID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []models.User
	for rows.Next() {
		var (
			email, phone, passwordHash, adDN sql.NullString
			status, role                     string
			createdAt, updatedAt             time.Time
			user                             models.User
		)
		if err := rows.Scan(
			&user.ID,
			&user.Username,
			&email,
			&phone,
			&status,
			&role,
			&passwordHash,
			&adDN,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, 0, err
		}
		user.Email = fromNullString(email)
		user.Phone = fromNullString(phone)
		user.Status = models.UserStatus(status)
		user.Role = models.UserRole(role)
		user.PasswordHash = fromNullString(passwordHash)
		user.AdDN = fromNullString(adDN)
		user.CreatedAt = createdAt
		user.UpdatedAt = updatedAt
		items = append(items, user)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *UserGroupRepository) ListGroups(ctx context.Context, userID string) ([]models.Group, error) {
	rows, err := r.db.QueryContext(ctx, `
        SELECT g.id, g.name, g.description, g.created_at
        FROM user_groups ug
        JOIN groups g ON g.id = ug.group_id
        WHERE ug.user_id = $1
        ORDER BY g.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []models.Group
	for rows.Next() {
		var group models.Group
		var description sql.NullString
		if err := rows.Scan(&group.ID, &group.Name, &description, &group.CreatedAt); err != nil {
			return nil, err
		}
		group.Description = fromNullString(description)
		items = append(items, group)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

type GroupPolicyRepository struct {
	db *sql.DB
}

func NewGroupPolicyRepository(db *sql.DB) *GroupPolicyRepository {
	return &GroupPolicyRepository{db: db}
}

func (r *GroupPolicyRepository) SetPolicy(ctx context.Context, groupID, policyID string) error {
	_, err := r.db.ExecContext(ctx, `
        INSERT INTO group_policies (group_id, policy_id, created_at)
        VALUES ($1,$2,now())
        ON CONFLICT (group_id) DO UPDATE SET policy_id = EXCLUDED.policy_id`, groupID, policyID)
	return err
}

func (r *GroupPolicyRepository) GetPolicy(ctx context.Context, groupID string) (string, error) {
	row := r.db.QueryRowContext(ctx, `
        SELECT policy_id FROM group_policies WHERE group_id = $1`, groupID)
	var policyID string
	if err := row.Scan(&policyID); err != nil {
		return "", mapNotFound(err)
	}
	return policyID, nil
}

func (r *GroupPolicyRepository) ClearPolicy(ctx context.Context, groupID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM group_policies WHERE group_id = $1`, groupID)
	return err
}

func buildUserListQuery(filter repository.UserListFilter) (string, []any) {
	base := "FROM users u"
	where := []string{}
	args := []any{}
	if filter.GroupID != "" {
		base += " JOIN user_groups ug ON ug.user_id = u.id"
		where = append(where, "ug.group_id = $"+itoa(len(args)+1))
		args = append(args, filter.GroupID)
	}
	if filter.Status != "" {
		where = append(where, "u.status = $"+itoa(len(args)+1))
		args = append(args, string(filter.Status))
	}
	if filter.Query != "" {
		where = append(where, "(u.username ILIKE $"+itoa(len(args)+1)+" OR u.email ILIKE $"+itoa(len(args)+1)+" OR u.phone ILIKE $"+itoa(len(args)+1)+")")
		args = append(args, "%"+filter.Query+"%")
	}
	if len(where) > 0 {
		base += " WHERE " + strings.Join(where, " AND ")
	}
	return base, args
}

func itoa(v int) string {
	return strconv.Itoa(v)
}
