package main

import (
	"log"
	"os"

	"github.com/qmish/2FA/internal/config"
	"github.com/qmish/2FA/internal/storage/postgres"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	db, err := postgres.OpenWithConfig(cfg.DBURL, postgres.PoolConfig{
		MaxOpenConns:    cfg.DBMaxOpenConns,
		MaxIdleConns:    cfg.DBMaxIdleConns,
		ConnMaxLifetime: cfg.DBConnMaxLifetime,
		ConnMaxIdleTime: cfg.DBConnMaxIdleTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	path := os.Getenv("MIGRATIONS_PATH")
	if path == "" {
		path = "migrations"
	}
	if err := postgres.ApplyMigrations(db, path); err != nil {
		log.Fatal(err)
	}
	log.Printf("migrations applied from %s", path)
}
