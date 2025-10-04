package storage

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a paste does not exist.
var ErrNotFound = errors.New("paste not found")

// Paste represents a stored paste entry.
type Paste struct {
	ID           string    `json:"id"`
	Content      string    `json:"content"`
	Syntax       string    `json:"syntax"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	PasswordHash string    `json:"password_hash,omitempty"`
	Size         int       `json:"size"`
}

// HasExpiration reports whether the paste has an expiry set.
func (p Paste) HasExpiration() bool {
	return !p.ExpiresAt.IsZero()
}

// Store defines the storage backend contract.
type Store interface {
	Save(ctx context.Context, paste *Paste) error
	Get(ctx context.Context, id string) (*Paste, error)
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
	Close() error
}
