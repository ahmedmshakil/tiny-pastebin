//go:build sqlite

package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"tiny-pastebin/internal/storage"
)

// Store implements storage.Store using SQLite.
type Store struct {
	db *sql.DB
}

// Open initializes the SQLite database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := initialize(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func initialize(db *sql.DB) error {
	schema := `
CREATE TABLE IF NOT EXISTS pastes (
    id TEXT PRIMARY KEY,
    content BLOB NOT NULL,
    syntax TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME,
    password_hash TEXT,
    size INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pastes_expires_at ON pastes (expires_at);
`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	return nil
}

// Save inserts or updates a paste.
func (s *Store) Save(ctx context.Context, paste *storage.Paste) error {
	if paste == nil {
		return errors.New("paste is nil")
	}

	paste.CreatedAt = paste.CreatedAt.UTC()
	paste.ExpiresAt = paste.ExpiresAt.UTC()

	const q = `
INSERT INTO pastes (id, content, syntax, created_at, expires_at, password_hash, size)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    content=excluded.content,
    syntax=excluded.syntax,
    created_at=excluded.created_at,
    expires_at=excluded.expires_at,
    password_hash=excluded.password_hash,
    size=excluded.size;
`
	_, err := s.db.ExecContext(ctx, q,
		paste.ID,
		[]byte(paste.Content),
		paste.Syntax,
		paste.CreatedAt,
		nullableTime(paste.ExpiresAt),
		nullString(paste.PasswordHash),
		paste.Size,
	)
	if err != nil {
		return fmt.Errorf("save paste: %w", err)
	}
	return nil
}

// Get fetches a paste by id.
func (s *Store) Get(ctx context.Context, id string) (*storage.Paste, error) {
	const q = `
SELECT id, content, syntax, created_at, expires_at, password_hash, size
FROM pastes WHERE id = ?;
`
	row := s.db.QueryRowContext(ctx, q, id)

	var (
		content   []byte
		syntax    string
		createdAt time.Time
		expiresAt sql.NullTime
		password  sql.NullString
		size      int
	)
	if err := row.Scan(&id, &content, &syntax, &createdAt, &expiresAt, &password, &size); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("query paste: %w", err)
	}

	paste := &storage.Paste{
		ID:           id,
		Content:      string(content),
		Syntax:       syntax,
		CreatedAt:    createdAt.UTC(),
		PasswordHash: password.String,
		Size:         size,
	}
	if expiresAt.Valid {
		paste.ExpiresAt = expiresAt.Time.UTC()
	}
	if password.Valid {
		paste.PasswordHash = password.String
	}
	return paste, nil
}

// Delete removes a paste by id.
func (s *Store) Delete(ctx context.Context, id string) error {
	const q = `DELETE FROM pastes WHERE id = ?;`
	res, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		return fmt.Errorf("delete paste: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// DeleteExpired removes all expired pastes.
func (s *Store) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	const q = `DELETE FROM pastes WHERE expires_at IS NOT NULL AND expires_at <= ?;`
	res, err := s.db.ExecContext(ctx, q, before.UTC())
	if err != nil {
		return 0, fmt.Errorf("delete expired: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return int(rows), nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
