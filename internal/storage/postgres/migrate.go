package postgres

import (
    "database/sql"
    "fmt"
    "os"
    "path/filepath"
    "sort"
    "strings"
)

func ApplyMigrations(db *sql.DB, dir string) error {
    if err := ensureSchemaMigrations(db); err != nil {
        return err
    }
    entries, err := os.ReadDir(dir)
    if err != nil {
        return err
    }
    var files []string
    for _, entry := range entries {
        if entry.IsDir() {
            continue
        }
        name := entry.Name()
        if strings.HasSuffix(name, ".sql") {
            files = append(files, name)
        }
    }
    sort.Strings(files)
    for _, name := range files {
        version := strings.SplitN(name, "_", 2)[0]
        applied, err := isMigrationApplied(db, version)
        if err != nil {
            return err
        }
        if applied {
            continue
        }
        path := filepath.Join(dir, name)
        content, err := os.ReadFile(path)
        if err != nil {
            return err
        }
        if err := applyMigration(db, version, string(content)); err != nil {
            return fmt.Errorf("apply %s: %w", name, err)
        }
    }
    return nil
}

func ensureSchemaMigrations(db *sql.DB) error {
    _, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )`)
    return err
}

func isMigrationApplied(db *sql.DB, version string) (bool, error) {
    row := db.QueryRow(`SELECT 1 FROM schema_migrations WHERE version = $1`, version)
    var v int
    if err := row.Scan(&v); err != nil {
        if err == sql.ErrNoRows {
            return false, nil
        }
        return false, err
    }
    return true, nil
}

func applyMigration(db *sql.DB, version string, sqlText string) error {
    tx, err := db.Begin()
    if err != nil {
        return err
    }
    if _, err := tx.Exec(sqlText); err != nil {
        _ = tx.Rollback()
        return err
    }
    if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
        _ = tx.Rollback()
        return err
    }
    return tx.Commit()
}
