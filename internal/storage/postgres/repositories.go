package postgres

import (
    "context"
    "database/sql"
    "time"

    "github.com/qmish/2FA/internal/models"
)

type UserRepository struct {
    db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
    return &UserRepository{db: db}
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
    row := r.db.QueryRowContext(ctx, `
        SELECT id, username, email, phone, status, password_hash, ad_dn, created_at, updated_at
        FROM users WHERE id = $1`, id)

    var (
        email, phone, passwordHash, adDN sql.NullString
        status                            string
        createdAt, updatedAt              time.Time
        user                              models.User
    )
    if err := row.Scan(
        &user.ID,
        &user.Username,
        &email,
        &phone,
        &status,
        &passwordHash,
        &adDN,
        &createdAt,
        &updatedAt,
    ); err != nil {
        return nil, err
    }

    user.Email = fromNullString(email)
    user.Phone = fromNullString(phone)
    user.Status = models.UserStatus(status)
    user.PasswordHash = fromNullString(passwordHash)
    user.AdDN = fromNullString(adDN)
    user.CreatedAt = createdAt
    user.UpdatedAt = updatedAt
    return &user, nil
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
    row := r.db.QueryRowContext(ctx, `
        SELECT id, username, email, phone, status, password_hash, ad_dn, created_at, updated_at
        FROM users WHERE username = $1`, username)

    var (
        email, phone, passwordHash, adDN sql.NullString
        status                            string
        createdAt, updatedAt              time.Time
        user                              models.User
    )
    if err := row.Scan(
        &user.ID,
        &user.Username,
        &email,
        &phone,
        &status,
        &passwordHash,
        &adDN,
        &createdAt,
        &updatedAt,
    ); err != nil {
        return nil, err
    }
    user.Email = fromNullString(email)
    user.Phone = fromNullString(phone)
    user.Status = models.UserStatus(status)
    user.PasswordHash = fromNullString(passwordHash)
    user.AdDN = fromNullString(adDN)
    user.CreatedAt = createdAt
    user.UpdatedAt = updatedAt
    return &user, nil
}

func (r *UserRepository) Create(ctx context.Context, u *models.User) error {
    _, err := r.db.ExecContext(ctx, `
        INSERT INTO users (id, username, email, phone, status, password_hash, ad_dn, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        u.ID,
        u.Username,
        nullString(u.Email),
        nullString(u.Phone),
        string(u.Status),
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
        SET email = $2, phone = $3, status = $4, password_hash = $5, ad_dn = $6, updated_at = $7
        WHERE id = $1`,
        u.ID,
        nullString(u.Email),
        nullString(u.Phone),
        string(u.Status),
        nullString(u.PasswordHash),
        nullString(u.AdDN),
        u.UpdatedAt,
    )
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
        INSERT INTO user_sessions (id, user_id, refresh_token_hash, ip, user_agent, expires_at, created_at, revoked_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        s.ID,
        s.UserID,
        s.RefreshTokenHash,
        nullString(s.IP),
        nullString(s.UserAgent),
        s.ExpiresAt,
        s.CreatedAt,
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
        SELECT id, user_id, refresh_token_hash, ip, user_agent, expires_at, created_at, revoked_at
        FROM user_sessions WHERE refresh_token_hash = $1`, hash)

    var (
        ip, userAgent sql.NullString
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
        &revokedAt,
    ); err != nil {
        return nil, err
    }
    s.IP = fromNullString(ip)
    s.UserAgent = fromNullString(userAgent)
    s.RevokedAt = fromNullTime(revokedAt)
    return &s, nil
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
            name      sql.NullString
            status    string
            lastSeen  sql.NullTime
            device    models.Device
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
        return nil, err
    }
    p.Status = models.PolicyStatus(status)
    return &p, nil
}

func (r *PolicyRepository) List(ctx context.Context) ([]models.Policy, error) {
    rows, err := r.db.QueryContext(ctx, `
        SELECT id, name, priority, status, created_at
        FROM policies ORDER BY priority ASC`)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var items []models.Policy
    for rows.Next() {
        var status string
        var p models.Policy
        if err := rows.Scan(&p.ID, &p.Name, &p.Priority, &status, &p.CreatedAt); err != nil {
            return nil, err
        }
        p.Status = models.PolicyStatus(status)
        items = append(items, p)
    }
    if err := rows.Err(); err != nil {
        return nil, err
    }
    return items, nil
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

type RadiusClientRepository struct {
    db *sql.DB
}

func NewRadiusClientRepository(db *sql.DB) *RadiusClientRepository {
    return &RadiusClientRepository{db: db}
}

func (r *RadiusClientRepository) GetByIP(ctx context.Context, ip string) (*models.RadiusClient, error) {
    row := r.db.QueryRowContext(ctx, `
        SELECT id, name, ip, secret, enabled, created_at
        FROM radius_clients WHERE ip = $1`, ip)
    var c models.RadiusClient
    if err := row.Scan(&c.ID, &c.Name, &c.IP, &c.Secret, &c.Enabled, &c.CreatedAt); err != nil {
        return nil, err
    }
    return &c, nil
}

func (r *RadiusClientRepository) List(ctx context.Context) ([]models.RadiusClient, error) {
    rows, err := r.db.QueryContext(ctx, `
        SELECT id, name, ip, secret, enabled, created_at
        FROM radius_clients ORDER BY created_at DESC`)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var items []models.RadiusClient
    for rows.Next() {
        var c models.RadiusClient
        if err := rows.Scan(&c.ID, &c.Name, &c.IP, &c.Secret, &c.Enabled, &c.CreatedAt); err != nil {
            return nil, err
        }
        items = append(items, c)
    }
    if err := rows.Err(); err != nil {
        return nil, err
    }
    return items, nil
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

func (r *AuditRepository) ListByActor(ctx context.Context, actorUserID string, limit int) ([]models.AuditEvent, error) {
    rows, err := r.db.QueryContext(ctx, `
        SELECT id, actor_user_id, action, entity_type, entity_id, payload, ip, created_at
        FROM audit_events WHERE actor_user_id = $1 ORDER BY created_at DESC LIMIT $2`,
        actorUserID, limit)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var items []models.AuditEvent
    for rows.Next() {
        var (
            actorID, entityID, payload, ip sql.NullString
            action, entityType              string
            e                               models.AuditEvent
        )
        if err := rows.Scan(&e.ID, &actorID, &action, &entityType, &entityID, &payload, &ip, &e.CreatedAt); err != nil {
            return nil, err
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
        return nil, err
    }
    return items, nil
}

func (r *AuditRepository) ListByEntity(ctx context.Context, entityType models.AuditEntityType, entityID string, limit int) ([]models.AuditEvent, error) {
    rows, err := r.db.QueryContext(ctx, `
        SELECT id, actor_user_id, action, entity_type, entity_id, payload, ip, created_at
        FROM audit_events WHERE entity_type = $1 AND entity_id = $2 ORDER BY created_at DESC LIMIT $3`,
        string(entityType), entityID, limit)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var items []models.AuditEvent
    for rows.Next() {
        var (
            actorID, entityIDValue, payload, ip sql.NullString
            action, entityTypeValue            string
            e                                  models.AuditEvent
        )
        if err := rows.Scan(&e.ID, &actorID, &action, &entityTypeValue, &entityIDValue, &payload, &ip, &e.CreatedAt); err != nil {
            return nil, err
        }
        e.ActorUserID = fromNullString(actorID)
        e.Action = models.AuditAction(action)
        e.EntityType = models.AuditEntityType(entityTypeValue)
        e.EntityID = fromNullString(entityIDValue)
        e.Payload = fromNullString(payload)
        e.IP = fromNullString(ip)
        items = append(items, e)
    }
    if err := rows.Err(); err != nil {
        return nil, err
    }
    return items, nil
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

func (r *LoginHistoryRepository) ListByUser(ctx context.Context, userID string, limit int) ([]models.LoginHistory, error) {
    rows, err := r.db.QueryContext(ctx, `
        SELECT id, user_id, channel, result, ip, device_id, created_at
        FROM login_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`, userID, limit)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var items []models.LoginHistory
    for rows.Next() {
        var (
            userIDValue, ip, deviceID sql.NullString
            channel, result           string
            h                         models.LoginHistory
        )
        if err := rows.Scan(&h.ID, &userIDValue, &channel, &result, &ip, &deviceID, &h.CreatedAt); err != nil {
            return nil, err
        }
        h.UserID = fromNullString(userIDValue)
        h.Channel = models.AuthChannel(channel)
        h.Result = models.AuthResult(result)
        h.IP = fromNullString(ip)
        h.DeviceID = fromNullString(deviceID)
        items = append(items, h)
    }
    if err := rows.Err(); err != nil {
        return nil, err
    }
    return items, nil
}

func (r *LoginHistoryRepository) ListByChannel(ctx context.Context, channel models.AuthChannel, limit int) ([]models.LoginHistory, error) {
    rows, err := r.db.QueryContext(ctx, `
        SELECT id, user_id, channel, result, ip, device_id, created_at
        FROM login_history WHERE channel = $1 ORDER BY created_at DESC LIMIT $2`, string(channel), limit)
    if err != nil {
        return nil, err
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
            return nil, err
        }
        h.UserID = fromNullString(userIDValue)
        h.Channel = models.AuthChannel(channelValue)
        h.Result = models.AuthResult(result)
        h.IP = fromNullString(ip)
        h.DeviceID = fromNullString(deviceID)
        items = append(items, h)
    }
    if err := rows.Err(); err != nil {
        return nil, err
    }
    return items, nil
}

func (r *LoginHistoryRepository) ListByPeriod(ctx context.Context, from, to time.Time, limit int) ([]models.LoginHistory, error) {
    rows, err := r.db.QueryContext(ctx, `
        SELECT id, user_id, channel, result, ip, device_id, created_at
        FROM login_history WHERE created_at BETWEEN $1 AND $2 ORDER BY created_at DESC LIMIT $3`, from, to, limit)
    if err != nil {
        return nil, err
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
            return nil, err
        }
        h.UserID = fromNullString(userIDValue)
        h.Channel = models.AuthChannel(channelValue)
        h.Result = models.AuthResult(result)
        h.IP = fromNullString(ip)
        h.DeviceID = fromNullString(deviceID)
        items = append(items, h)
    }
    if err := rows.Err(); err != nil {
        return nil, err
    }
    return items, nil
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

func (r *RadiusRequestRepository) ListByClient(ctx context.Context, clientID string, limit int) ([]models.RadiusRequest, error) {
    rows, err := r.db.QueryContext(ctx, `
        SELECT id, client_id, username, nas_ip, result, request_id, request_attrs, response_attrs, created_at
        FROM radius_requests WHERE client_id = $1 ORDER BY created_at DESC LIMIT $2`, clientID, limit)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var items []models.RadiusRequest
    for rows.Next() {
        var (
            clientIDValue, username, nasIP, requestID, requestAttrs, responseAttrs sql.NullString
            resultValue                                                         string
            req                                                                 models.RadiusRequest
        )
        if err := rows.Scan(&req.ID, &clientIDValue, &username, &nasIP, &resultValue, &requestID, &requestAttrs, &responseAttrs, &req.CreatedAt); err != nil {
            return nil, err
        }
        req.ClientID = fromNullString(clientIDValue)
        req.Username = fromNullString(username)
        req.NASIP = fromNullString(nasIP)
        req.Result = models.RadiusResult(resultValue)
        req.RequestID = fromNullString(requestID)
        req.RequestAttrs = fromNullString(requestAttrs)
        req.ResponseAttrs = fromNullString(responseAttrs)
        items = append(items, req)
    }
    if err := rows.Err(); err != nil {
        return nil, err
    }
    return items, nil
}

func (r *RadiusRequestRepository) ListByUser(ctx context.Context, username string, limit int) ([]models.RadiusRequest, error) {
    rows, err := r.db.QueryContext(ctx, `
        SELECT id, client_id, username, nas_ip, result, request_id, request_attrs, response_attrs, created_at
        FROM radius_requests WHERE username = $1 ORDER BY created_at DESC LIMIT $2`, username, limit)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var items []models.RadiusRequest
    for rows.Next() {
        var (
            clientIDValue, usernameValue, nasIP, requestID, requestAttrs, responseAttrs sql.NullString
            resultValue                                                               string
            req                                                                       models.RadiusRequest
        )
        if err := rows.Scan(&req.ID, &clientIDValue, &usernameValue, &nasIP, &resultValue, &requestID, &requestAttrs, &responseAttrs, &req.CreatedAt); err != nil {
            return nil, err
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
        return nil, err
    }
    return items, nil
}

func (r *RadiusRequestRepository) UpdateResult(ctx context.Context, id string, result models.RadiusResult) error {
    _, err := r.db.ExecContext(ctx, `UPDATE radius_requests SET result = $2 WHERE id = $1`, id, string(result))
    return err
}
