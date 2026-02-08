package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	_ "github.com/lib/pq"
)

var ErrEmptyDSN = errors.New("empty dsn")

type PoolConfig struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	PingTimeout     time.Duration
}

func Open(dsn string) (*sql.DB, error) {
	return OpenWithConfig(dsn, PoolConfig{})
}

func OpenWithConfig(dsn string, cfg PoolConfig) (*sql.DB, error) {
	if dsn == "" {
		return nil, ErrEmptyDSN
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	if err := pingWithTimeout(db, cfg.PingTimeout); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func pingWithTimeout(db *sql.DB, timeout time.Duration) error {
	if timeout <= 0 {
		return db.Ping()
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return db.PingContext(ctx)
}
