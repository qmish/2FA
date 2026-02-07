package postgres

import (
	"context"
	"database/sql"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/internal/repository"
)

func TestUserRepositoryGetByID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewUserRepository(db)
	now := time.Now()
	rows := sqlmock.NewRows([]string{
		"id", "username", "email", "phone", "status", "role", "password_hash", "ad_dn", "created_at", "updated_at",
	}).AddRow("u1", "alice", "a@example.com", "+79990000000", "active", "admin", "hash", "cn=alice", now, now)

	mock.ExpectQuery("FROM users WHERE id = \\$1").WithArgs("u1").WillReturnRows(rows)

	got, err := repo.GetByID(context.Background(), "u1")
	if err != nil {
		t.Fatalf("GetByID error: %v", err)
	}
	if got.Username != "alice" || got.Status != models.UserActive || got.Role != models.RoleAdmin {
		t.Fatalf("unexpected user: %+v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestDeviceRepositoryListByUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewDeviceRepository(db)
	now := time.Now()
	rows := sqlmock.NewRows([]string{
		"id", "user_id", "type", "name", "status", "last_seen_at", "created_at",
	}).AddRow("d1", "u1", "mobile", "iphone", "active", now, now)

	mock.ExpectQuery("FROM devices WHERE user_id = \\$1").WithArgs("u1").WillReturnRows(rows)

	items, err := repo.ListByUser(context.Background(), "u1")
	if err != nil {
		t.Fatalf("ListByUser error: %v", err)
	}
	if len(items) != 1 || items[0].Type != models.DeviceMobile {
		t.Fatalf("unexpected items: %+v", items)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestRadiusRequestRepositoryCreate(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRadiusRequestRepository(db)
	req := &models.RadiusRequest{
		ID:        "r1",
		ClientID:  "c1",
		Username:  "alice",
		NASIP:     "10.0.0.1",
		Result:    models.RadiusAccept,
		RequestID: "req-1",
		CreatedAt: time.Now(),
	}

	mock.ExpectExec("INSERT INTO radius_requests").
		WithArgs(
			req.ID,
			sql.NullString{String: req.ClientID, Valid: true},
			sql.NullString{String: req.Username, Valid: true},
			sql.NullString{String: req.NASIP, Valid: true},
			string(req.Result),
			sql.NullString{String: req.RequestID, Valid: true},
			sql.NullString{},
			sql.NullString{},
			req.CreatedAt,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Create(context.Background(), req); err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestAuditRepositoryCreate(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewAuditRepository(db)
	evt := &models.AuditEvent{
		ID:          "a1",
		ActorUserID: "u1",
		Action:      models.AuditCreate,
		EntityType:  models.AuditEntityUser,
		EntityID:    "u2",
		Payload:     "{}",
		IP:          "127.0.0.1",
		CreatedAt:   time.Now(),
	}

	mock.ExpectExec("INSERT INTO audit_events").
		WithArgs(
			evt.ID,
			sql.NullString{String: evt.ActorUserID, Valid: true},
			string(evt.Action),
			string(evt.EntityType),
			sql.NullString{String: evt.EntityID, Valid: true},
			sql.NullString{String: evt.Payload, Valid: true},
			sql.NullString{String: evt.IP, Valid: true},
			evt.CreatedAt,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Create(context.Background(), evt); err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestAuditRepositoryListFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewAuditRepository(db)
	from := time.Date(2026, 2, 5, 15, 0, 0, 0, time.UTC)
	to := time.Date(2026, 2, 6, 15, 0, 0, 0, time.UTC)
	filter := repository.AuditFilter{
		ActorUserID: "u1",
		EntityType:  models.AuditEntitySession,
		Action:      models.AuditLogout,
		EntityID:    "s1",
		IP:          "127.0.0.1",
		Payload:     "payload",
		Query:       "search",
		From:        from,
		To:          to,
	}

	countQuery := "SELECT COUNT(*) FROM audit_events WHERE actor_user_id = $1 AND entity_type = $2 AND action = $3 AND entity_id = $4 AND ip = $5 AND payload = $6 AND (actor_user_id ILIKE $7 OR entity_id ILIKE $7 OR payload ILIKE $7 OR ip ILIKE $7) AND created_at >= $8 AND created_at <= $9"
	mock.ExpectQuery(regexp.QuoteMeta(countQuery)).
		WithArgs("u1", "session", "logout", "s1", "127.0.0.1", "payload", "%search%", from, to).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	selectQuery := "SELECT id, actor_user_id, action, entity_type, entity_id, payload, ip, created_at FROM audit_events WHERE actor_user_id = $1 AND entity_type = $2 AND action = $3 AND entity_id = $4 AND ip = $5 AND payload = $6 AND (actor_user_id ILIKE $7 OR entity_id ILIKE $7 OR payload ILIKE $7 OR ip ILIKE $7) AND created_at >= $8 AND created_at <= $9 ORDER BY created_at DESC LIMIT $10 OFFSET $11"
	rows := sqlmock.NewRows([]string{
		"id", "actor_user_id", "action", "entity_type", "entity_id", "payload", "ip", "created_at",
	}).AddRow("a1", "u1", "logout", "session", "s1", "p1", "127.0.0.1", from)
	mock.ExpectQuery(regexp.QuoteMeta(selectQuery)).
		WithArgs("u1", "session", "logout", "s1", "127.0.0.1", "payload", "%search%", from, to, 10, 0).
		WillReturnRows(rows)

	items, total, err := repo.List(context.Background(), filter, 10, 0)
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != "a1" || items[0].Payload != "p1" {
		t.Fatalf("unexpected result: total=%d items=%+v", total, items)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestLoginHistoryRepositoryList(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewLoginHistoryRepository(db)
	now := time.Now()
	rows := sqlmock.NewRows([]string{
		"id", "user_id", "channel", "result", "ip", "device_id", "created_at",
	}).AddRow("l1", "u1", "web", "success", "127.0.0.1", "d1", now)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM login_history WHERE user_id = \\$1").
		WithArgs("u1").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("FROM login_history WHERE user_id = \\$1").
		WithArgs("u1", 10, 0).WillReturnRows(rows)

	items, _, err := repo.List(context.Background(), repository.LoginHistoryFilter{UserID: "u1"}, 10, 0)
	if err != nil {
		t.Fatalf("ListByUser error: %v", err)
	}
	if len(items) != 1 || items[0].Result != models.AuthSuccess {
		t.Fatalf("unexpected items: %+v", items)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestLoginHistoryRepositoryListWithIPDevice(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewLoginHistoryRepository(db)
	now := time.Now()
	rows := sqlmock.NewRows([]string{
		"id", "user_id", "channel", "result", "ip", "device_id", "created_at",
	}).AddRow("l2", "u2", "web", "deny", "127.0.0.1", "device-1", now)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM login_history WHERE ip = \\$1 AND device_id = \\$2").
		WithArgs("127.0.0.1", "device-1").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("FROM login_history WHERE ip = \\$1 AND device_id = \\$2").
		WithArgs("127.0.0.1", "device-1", 10, 0).WillReturnRows(rows)

	items, _, err := repo.List(context.Background(), repository.LoginHistoryFilter{
		IP:       "127.0.0.1",
		DeviceID: "device-1",
	}, 10, 0)
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if len(items) != 1 || items[0].DeviceID != "device-1" {
		t.Fatalf("unexpected items: %+v", items)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestLoginHistoryRepositoryCountFailures(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewLoginHistoryRepository(db)
	since := time.Now().Add(-time.Minute)
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM login_history").
		WithArgs("u1", "deny", since).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(4))

	count, err := repo.CountFailures(context.Background(), "u1", since)
	if err != nil || count != 4 {
		t.Fatalf("unexpected result: %v %d", err, count)
	}
}

func TestRolePermissionRepositoryListByRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRolePermissionRepository(db)
	rows := sqlmock.NewRows([]string{"permission"}).
		AddRow("admin.users.read").
		AddRow("admin.audit.read")

	mock.ExpectQuery("FROM role_permissions WHERE role = \\$1").
		WithArgs("admin").WillReturnRows(rows)

	perms, err := repo.ListByRole(context.Background(), models.RoleAdmin)
	if err != nil {
		t.Fatalf("ListByRole error: %v", err)
	}
	if len(perms) != 2 {
		t.Fatalf("unexpected perms: %+v", perms)
	}
}

func TestRolePermissionRepositorySetRolePermissions(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRolePermissionRepository(db)

	mock.ExpectBegin()
	mock.ExpectExec("DELETE FROM role_permissions WHERE role = \\$1").
		WithArgs("admin").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO role_permissions").
		WithArgs("admin", "admin.users.read").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = repo.SetRolePermissions(context.Background(), models.RoleAdmin, []models.Permission{models.PermissionAdminUsersRead})
	if err != nil {
		t.Fatalf("SetRolePermissions error: %v", err)
	}
}

func TestChallengeRepositoryGetByID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewChallengeRepository(db)
	now := time.Now()
	rows := sqlmock.NewRows([]string{
		"id", "user_id", "method", "status", "code_hash", "provider_id", "expires_at", "created_at", "updated_at",
	}).AddRow("c1", "u1", "otp", "created", "hash", "prov", now, now, now)

	mock.ExpectQuery("FROM challenges WHERE id = \\$1").
		WithArgs("c1").WillReturnRows(rows)

	c, err := repo.GetByID(context.Background(), "c1")
	if err != nil {
		t.Fatalf("GetByID error: %v", err)
	}
	if c.Method != models.MethodOTP || c.Status != models.ChallengeCreated {
		t.Fatalf("unexpected challenge: %+v", c)
	}
}

func TestChallengeRepositoryGetActiveByUserAndMethod(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewChallengeRepository(db)
	now := time.Now()
	rows := sqlmock.NewRows([]string{
		"id", "user_id", "method", "status", "code_hash", "provider_id", "expires_at", "created_at", "updated_at",
	}).AddRow("c1", "u1", "otp", "sent", "hash", "prov", now, now, now)

	mock.ExpectQuery("FROM challenges").
		WithArgs("u1", "otp").
		WillReturnRows(rows)

	c, err := repo.GetActiveByUserAndMethod(context.Background(), "u1", models.MethodOTP)
	if err != nil {
		t.Fatalf("GetActiveByUserAndMethod error: %v", err)
	}
	if c.ID != "c1" || c.Status != models.ChallengeSent {
		t.Fatalf("unexpected challenge: %+v", c)
	}
}

func TestChallengeRepositoryCreate(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewChallengeRepository(db)
	now := time.Now()
	c := &models.Challenge{
		ID:         "c1",
		UserID:     "u1",
		Method:     models.MethodOTP,
		Status:     models.ChallengeCreated,
		CodeHash:   "hash",
		ProviderID: "prov",
		ExpiresAt:  now,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	mock.ExpectExec("INSERT INTO challenges").
		WithArgs(
			c.ID, c.UserID, string(c.Method), string(c.Status),
			sql.NullString{String: c.CodeHash, Valid: true},
			sql.NullString{String: c.ProviderID, Valid: true},
			c.ExpiresAt, c.CreatedAt, c.UpdatedAt,
		).WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Create(context.Background(), c); err != nil {
		t.Fatalf("Create error: %v", err)
	}
}

func TestChallengeRepositoryUpdateDelivery(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewChallengeRepository(db)
	mock.ExpectExec("UPDATE challenges SET provider_id = \\$2, status = \\$3").
		WithArgs("c1", sql.NullString{String: "prov", Valid: true}, "sent").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpdateDelivery(context.Background(), "c1", "prov", models.ChallengeSent); err != nil {
		t.Fatalf("UpdateDelivery error: %v", err)
	}
}

func TestChallengeRepositoryMarkExpired(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewChallengeRepository(db)
	now := time.Now()
	mock.ExpectExec("UPDATE challenges SET status = 'expired'").
		WithArgs(now).WillReturnResult(sqlmock.NewResult(1, 2))

	n, err := repo.MarkExpired(context.Background(), now)
	if err != nil || n != 2 {
		t.Fatalf("unexpected result: %v %d", err, n)
	}
}

func TestSessionRepositoryList(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewSessionRepository(db)
	now := time.Now()
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM user_sessions WHERE user_id = \\$1").
		WithArgs("u1").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	rows := sqlmock.NewRows([]string{
		"id", "user_id", "refresh_token_hash", "ip", "user_agent", "expires_at", "created_at", "last_seen_at", "revoked_at",
	}).AddRow("s1", "u1", "hash", "127.0.0.1", "ua", now, now, now, nil)
	mock.ExpectQuery("FROM user_sessions WHERE user_id = \\$1").
		WithArgs("u1", 10, 0).WillReturnRows(rows)

	items, total, err := repo.List(context.Background(), repository.SessionListFilter{UserID: "u1"}, 10, 0)
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("unexpected result: total=%d len=%d err=%v", total, len(items), err)
	}
}

func TestSessionRepositoryListWithFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewSessionRepository(db)
	now := time.Now()
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM user_sessions WHERE user_id = \\$1 AND ip = \\$2 AND user_agent = \\$3").
		WithArgs("u1", "127.0.0.1", "ua").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	rows := sqlmock.NewRows([]string{
		"id", "user_id", "refresh_token_hash", "ip", "user_agent", "expires_at", "created_at", "last_seen_at", "revoked_at",
	}).AddRow("s1", "u1", "hash", "127.0.0.1", "ua", now, now, now, nil)
	mock.ExpectQuery("FROM user_sessions WHERE user_id = \\$1 AND ip = \\$2 AND user_agent = \\$3").
		WithArgs("u1", "127.0.0.1", "ua", 10, 0).WillReturnRows(rows)

	items, total, err := repo.List(context.Background(), repository.SessionListFilter{
		UserID:    "u1",
		IP:        "127.0.0.1",
		UserAgent: "ua",
	}, 10, 0)
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("unexpected result: total=%d len=%d err=%v", total, len(items), err)
	}
}

func TestSessionRepositoryRevokeAllByUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewSessionRepository(db)
	now := time.Now()
	mock.ExpectExec("UPDATE user_sessions SET revoked_at = \\$2").
		WithArgs("u1", now).
		WillReturnResult(sqlmock.NewResult(1, 2))

	if err := repo.RevokeAllByUser(context.Background(), "u1", "", now); err != nil {
		t.Fatalf("RevokeAllByUser error: %v", err)
	}
}

func TestSessionRepositoryTouch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewSessionRepository(db)
	now := time.Now()
	mock.ExpectExec("UPDATE user_sessions SET last_seen_at = \\$2").
		WithArgs("s1", now).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Touch(context.Background(), "s1", now); err != nil {
		t.Fatalf("Touch error: %v", err)
	}
}

func TestLockoutRepositoryCreate(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewLockoutRepository(db)
	now := time.Now()
	lockout := &models.Lockout{
		ID:        "l1",
		UserID:    "u1",
		IP:        "127.0.0.1",
		Reason:    "too_many_attempts",
		ExpiresAt: now.Add(time.Minute),
		CreatedAt: now,
	}

	mock.ExpectExec("INSERT INTO lockouts").
		WithArgs(
			lockout.ID,
			sql.NullString{String: lockout.UserID, Valid: true},
			lockout.IP,
			lockout.Reason,
			lockout.ExpiresAt,
			lockout.CreatedAt,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Create(context.Background(), lockout); err != nil {
		t.Fatalf("Create error: %v", err)
	}
}

func TestLockoutRepositoryGetActive(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewLockoutRepository(db)
	now := time.Now()
	rows := sqlmock.NewRows([]string{
		"id", "user_id", "ip", "reason", "expires_at", "created_at",
	}).AddRow("l1", "u1", "127.0.0.1", "too_many_attempts", now.Add(time.Minute), now)

	mock.ExpectQuery("FROM lockouts").
		WithArgs("u1", "127.0.0.1", now).
		WillReturnRows(rows)

	got, err := repo.GetActive(context.Background(), "u1", "127.0.0.1", now)
	if err != nil {
		t.Fatalf("GetActive error: %v", err)
	}
	if got.ID != "l1" || got.Reason != "too_many_attempts" {
		t.Fatalf("unexpected lockout: %+v", got)
	}
}

func TestLockoutRepositoryClearExpired(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewLockoutRepository(db)
	now := time.Now()
	mock.ExpectExec("DELETE FROM lockouts").
		WithArgs(now).
		WillReturnResult(sqlmock.NewResult(1, 3))

	n, err := repo.ClearExpired(context.Background(), now)
	if err != nil || n != 3 {
		t.Fatalf("unexpected result: %v %d", err, n)
	}
}

func TestLockoutRepositoryList(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewLockoutRepository(db)
	now := time.Now()
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM lockouts WHERE user_id = \\$1").
		WithArgs("u1").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	rows := sqlmock.NewRows([]string{
		"id", "user_id", "ip", "reason", "expires_at", "created_at",
	}).AddRow("l1", "u1", "127.0.0.1", "too_many_attempts", now.Add(time.Minute), now)
	mock.ExpectQuery("FROM lockouts WHERE user_id = \\$1").
		WithArgs("u1", 10, 0).WillReturnRows(rows)

	items, total, err := repo.List(context.Background(), repository.LockoutFilter{UserID: "u1"}, 10, 0)
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("unexpected result: %v %d %d", err, total, len(items))
	}
}

func TestLockoutRepositoryListActiveOnly(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewLockoutRepository(db)
	now := time.Now()
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM lockouts WHERE expires_at > \\$1").
		WithArgs(now).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("FROM lockouts WHERE expires_at > \\$1").
		WithArgs(now, 10, 0).WillReturnRows(sqlmock.NewRows([]string{
		"id", "user_id", "ip", "reason", "expires_at", "created_at",
	}))

	_, _, err = repo.List(context.Background(), repository.LockoutFilter{ActiveOnly: true, Now: now}, 10, 0)
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
}

func TestLockoutRepositoryClearByFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewLockoutRepository(db)
	mock.ExpectExec("DELETE FROM lockouts WHERE user_id = \\$1 AND ip = \\$2").
		WithArgs("u1", "127.0.0.1").
		WillReturnResult(sqlmock.NewResult(1, 2))

	if err := repo.ClearByFilter(context.Background(), repository.LockoutFilter{UserID: "u1", IP: "127.0.0.1"}); err != nil {
		t.Fatalf("ClearByFilter error: %v", err)
	}
}

func TestGroupRepositoryGetByName(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewGroupRepository(db)
	now := time.Now()
	rows := sqlmock.NewRows([]string{"id", "name", "description", "created_at"}).
		AddRow("g1", "admins", "admins group", now)
	mock.ExpectQuery("FROM groups WHERE name = \\$1").
		WithArgs("admins").WillReturnRows(rows)

	g, err := repo.GetByName(context.Background(), "admins")
	if err != nil {
		t.Fatalf("GetByName error: %v", err)
	}
	if g.Name != "admins" {
		t.Fatalf("unexpected group: %+v", g)
	}
}

func TestUserGroupRepositoryListUsers(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewUserGroupRepository(db)
	now := time.Now()
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM user_groups WHERE group_id = \\$1").
		WithArgs("g1").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	rows := sqlmock.NewRows([]string{
		"id", "username", "email", "phone", "status", "role", "password_hash", "ad_dn", "created_at", "updated_at",
	}).AddRow("u1", "alice", "a@example.com", "+79990000000", "active", "admin", "hash", "dn", now, now)
	mock.ExpectQuery("FROM user_groups ug").
		WithArgs("g1", 10, 0).WillReturnRows(rows)

	users, total, err := repo.ListUsers(context.Background(), "g1", 10, 0)
	if err != nil || total != 1 || len(users) != 1 {
		t.Fatalf("unexpected result: total=%d len=%d err=%v", total, len(users), err)
	}
}

func TestUserGroupRepositoryListGroups(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewUserGroupRepository(db)
	now := time.Now()
	rows := sqlmock.NewRows([]string{"id", "name", "description", "created_at"}).
		AddRow("g1", "ops", "ops team", now)
	mock.ExpectQuery("FROM user_groups ug").
		WithArgs("u1").WillReturnRows(rows)

	groups, err := repo.ListGroups(context.Background(), "u1")
	if err != nil || len(groups) != 1 {
		t.Fatalf("unexpected result: len=%d err=%v", len(groups), err)
	}
	if groups[0].Name != "ops" {
		t.Fatalf("unexpected group: %+v", groups[0])
	}
}

func TestOTPSecretRepositoryGetActiveByUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewOTPSecretRepository(db)
	now := time.Now()
	rows := sqlmock.NewRows([]string{"id", "user_id", "secret", "issuer", "digits", "period", "enabled", "created_at"}).
		AddRow("s1", "u1", "secret", "2FA", 6, 30, true, now)
	mock.ExpectQuery("FROM otp_secrets WHERE user_id = \\$1 AND enabled = true").
		WithArgs("u1").WillReturnRows(rows)

	got, err := repo.GetActiveByUser(context.Background(), "u1")
	if err != nil {
		t.Fatalf("GetActiveByUser error: %v", err)
	}
	if got.UserID != "u1" || got.Secret != "secret" || got.Digits != 6 || got.Period != 30 {
		t.Fatalf("unexpected secret: %+v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestOTPSecretRepositoryCreate(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewOTPSecretRepository(db)
	now := time.Now()
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO otp_secrets (id, user_id, secret, issuer, digits, period, enabled, created_at)")).
		WithArgs("s1", "u1", "secret", sql.NullString{String: "2FA", Valid: true}, 6, 30, true, now).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Create(context.Background(), &models.OTPSecret{
		ID:        "s1",
		UserID:    "u1",
		Secret:    "secret",
		Issuer:    "2FA",
		Digits:    6,
		Period:    30,
		Enabled:   true,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestOTPSecretRepositoryDisable(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewOTPSecretRepository(db)
	mock.ExpectExec("UPDATE otp_secrets SET enabled = false WHERE id = \\$1").
		WithArgs("s1").WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Disable(context.Background(), "s1"); err != nil {
		t.Fatalf("Disable error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestInviteRepositoryCreateGetMarkUsed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewInviteRepository(db)
	now := time.Now()
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO invites (id, token_hash, email, phone, role, status, expires_at, created_at, used_at, used_by)")).
		WithArgs("i1", "hash", sql.NullString{String: "a@example.com", Valid: true}, sql.NullString{String: "", Valid: false}, "user", "pending", now.Add(time.Hour), now, sql.NullTime{}, sql.NullString{}).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Create(context.Background(), &models.Invite{
		ID:        "i1",
		TokenHash: "hash",
		Email:     "a@example.com",
		Role:      models.RoleUser,
		Status:    models.InvitePending,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("Create error: %v", err)
	}

	rows := sqlmock.NewRows([]string{"id", "token_hash", "email", "phone", "role", "status", "expires_at", "created_at", "used_at", "used_by"}).
		AddRow("i1", "hash", "a@example.com", nil, "user", "pending", now.Add(time.Hour), now, nil, nil)
	mock.ExpectQuery("FROM invites WHERE token_hash = \\$1").
		WithArgs("hash").WillReturnRows(rows)

	invite, err := repo.GetByTokenHash(context.Background(), "hash")
	if err != nil || invite.ID != "i1" {
		t.Fatalf("unexpected invite: %+v err=%v", invite, err)
	}

	mock.ExpectExec("UPDATE invites SET status = 'used', used_at = \\$2, used_by = \\$3 WHERE id = \\$1").
		WithArgs("i1", now, sql.NullString{String: "u1", Valid: true}).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.MarkUsed(context.Background(), "i1", "u1", now); err != nil {
		t.Fatalf("MarkUsed error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestRecoveryCodeRepositoryConsume(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRecoveryCodeRepository(db)
	now := time.Now()
	mock.ExpectExec(regexp.QuoteMeta(`
        UPDATE recovery_codes
        SET used_at = $3
        WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`)).
		WithArgs("u1", "hash1", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	ok, err := repo.Consume(context.Background(), "u1", "hash1", now)
	if err != nil {
		t.Fatalf("Consume error: %v", err)
	}
	if !ok {
		t.Fatalf("expected consume to succeed")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
