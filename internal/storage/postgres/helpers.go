package postgres

import (
    "database/sql"
    "errors"
    "time"

    "github.com/qmish/2FA/internal/repository"
)

func nullString(s string) sql.NullString {
    if s == "" {
        return sql.NullString{}
    }
    return sql.NullString{String: s, Valid: true}
}

func nullTime(t *time.Time) sql.NullTime {
    if t == nil {
        return sql.NullTime{}
    }
    return sql.NullTime{Time: *t, Valid: true}
}

func fromNullString(ns sql.NullString) string {
    if ns.Valid {
        return ns.String
    }
    return ""
}

func fromNullTime(nt sql.NullTime) *time.Time {
    if nt.Valid {
        t := nt.Time
        return &t
    }
    return nil
}

func mapNotFound(err error) error {
    if errors.Is(err, sql.ErrNoRows) {
        return repository.ErrNotFound
    }
    return err
}
