package database

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps a *sql.DB connection to the Sieve SQLite database.
type DB struct {
	*sql.DB
}

// New opens (or creates) the SQLite database at path, enables WAL mode and
// foreign keys, and runs schema migrations. The returned DB is ready for use.
func New(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Restrict DB file permissions to owner only.
	os.Chmod(path, 0600)

	// Enable WAL mode for better concurrent read performance.
	if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("enable WAL mode: %w", err)
	}

	// Enable foreign key enforcement (off by default in SQLite).
	if _, err := sqlDB.Exec("PRAGMA foreign_keys=ON"); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	db := &DB{DB: sqlDB}

	if err := db.migrate(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	return db, nil
}

// Close closes the underlying database connection.
func (db *DB) Close() error {
	return db.DB.Close()
}

// migrate runs all schema migrations in order.
func (db *DB) migrate() error {
	const schema = `
	CREATE TABLE IF NOT EXISTS connections (
		id              TEXT PRIMARY KEY,
		connector_type  TEXT NOT NULL,
		display_name    TEXT NOT NULL,
		config          TEXT NOT NULL,
		created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS policies (
		id              TEXT PRIMARY KEY,
		name            TEXT NOT NULL UNIQUE,
		policy_type     TEXT NOT NULL,
		policy_config   TEXT NOT NULL,
		created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS tokens (
		id               TEXT PRIMARY KEY,
		name             TEXT NOT NULL UNIQUE,
		token_hash       TEXT NOT NULL,
		connections      TEXT NOT NULL,
		policy_ids       TEXT NOT NULL,
		created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at       DATETIME,
		revoked          INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS approval_queue (
		id            TEXT PRIMARY KEY,
		token_id      TEXT NOT NULL,
		connection_id TEXT NOT NULL,
		operation     TEXT NOT NULL,
		request_data  TEXT NOT NULL,
		status        TEXT NOT NULL DEFAULT 'pending',
		created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
		resolved_at   DATETIME,
		resolved_by   TEXT
	);

	CREATE TABLE IF NOT EXISTS audit_log (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp         DATETIME DEFAULT CURRENT_TIMESTAMP,
		token_id          TEXT NOT NULL,
		token_name        TEXT NOT NULL,
		connection_id     TEXT NOT NULL,
		operation         TEXT NOT NULL,
		params            TEXT,
		policy_result     TEXT NOT NULL,
		response_summary  TEXT,
		duration_ms       INTEGER
	);
	`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("execute schema: %w", err)
	}

	// Migration: rename policy_id -> policy_ids (JSON array) if the old column exists.
	// SQLite doesn't support ALTER COLUMN, so we check if the old column exists
	// and add the new one if needed, copying data as a single-element JSON array.
	var hasOldColumn bool
	rows, err := db.Query("PRAGMA table_info(tokens)")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var cid int
			var name, typ string
			var notNull, pk int
			var dflt *string
			if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
				continue
			}
			if name == "policy_id" {
				hasOldColumn = true
			}
		}
	}

	// Migrate existing Gmail connections to the new "google" connector type.
	db.Exec(`UPDATE connections SET connector_type = 'google' WHERE connector_type = 'gmail'`)

	if hasOldColumn {
		// SQLite doesn't support DROP COLUMN in older versions, so we rebuild
		// the table to replace policy_id (TEXT) with policy_ids (JSON array).
		// Each step is checked — if any fails, the migration stops and the
		// error propagates so the database isn't left in an inconsistent state.
		steps := []string{
			`CREATE TABLE tokens_new (
				id               TEXT PRIMARY KEY,
				name             TEXT NOT NULL UNIQUE,
				token_hash       TEXT NOT NULL,
				connections      TEXT NOT NULL,
				policy_ids       TEXT NOT NULL,
				created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
				expires_at       DATETIME,
				revoked          INTEGER DEFAULT 0
			)`,
			`INSERT INTO tokens_new (id, name, token_hash, connections, policy_ids, created_at, expires_at, revoked)
				SELECT id, name, token_hash, connections, '["' || policy_id || '"]', created_at, expires_at, revoked FROM tokens`,
			`DROP TABLE tokens`,
			`ALTER TABLE tokens_new RENAME TO tokens`,
		}
		for _, stmt := range steps {
			if _, err := db.Exec(stmt); err != nil {
				return fmt.Errorf("migrate tokens table: %w", err)
			}
		}
	}

	return nil
}
