package postgres

import (
    "context"
    "database/sql"
    "testing"
    "time"

    "github.com/DATA-DOG/go-sqlmock"
    "github.com/qmish/2FA/internal/models"
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
        "id", "username", "email", "phone", "status", "password_hash", "ad_dn", "created_at", "updated_at",
    }).AddRow("u1", "alice", "a@example.com", "+79990000000", "active", "hash", "cn=alice", now, now)

    mock.ExpectQuery("FROM users WHERE id = \\$1").WithArgs("u1").WillReturnRows(rows)

    got, err := repo.GetByID(context.Background(), "u1")
    if err != nil {
        t.Fatalf("GetByID error: %v", err)
    }
    if got.Username != "alice" || got.Status != models.UserActive {
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

func TestLoginHistoryRepositoryListByUser(t *testing.T) {
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

    mock.ExpectQuery("FROM login_history WHERE user_id = \\$1").WithArgs("u1", 10).WillReturnRows(rows)

    items, err := repo.ListByUser(context.Background(), "u1", 10)
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
