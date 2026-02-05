package postgres

import (
    "database/sql"
    "errors"

    _ "github.com/lib/pq"
)

var ErrEmptyDSN = errors.New("empty dsn")

func Open(dsn string) (*sql.DB, error) {
    if dsn == "" {
        return nil, ErrEmptyDSN
    }
    db, err := sql.Open("postgres", dsn)
    if err != nil {
        return nil, err
    }
    if err := db.Ping(); err != nil {
        _ = db.Close()
        return nil, err
    }
    return db, nil
}
