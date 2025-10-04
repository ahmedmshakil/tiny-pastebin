package boltstore

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"tiny-pastebin/internal/storage"
)

var (
	pasteBucket  = []byte("pastes")
	expireBucket = []byte("expires")
)

// Store implements storage.Store backed by BoltDB.
type Store struct {
	db *bolt.DB
}

// Open initializes a BoltDB-backed store located at path.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bolt db: %w", err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(pasteBucket); err != nil {
			return fmt.Errorf("create paste bucket: %w", err)
		}
		if _, err := tx.CreateBucketIfNotExists(expireBucket); err != nil {
			return fmt.Errorf("create expire bucket: %w", err)
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

// Save persists or updates a paste entry.
func (s *Store) Save(ctx context.Context, paste *storage.Paste) error {
	if paste == nil {
		return errors.New("paste is nil")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Normalize timestamps to UTC for consistency.
	paste.CreatedAt = paste.CreatedAt.UTC()
	paste.ExpiresAt = paste.ExpiresAt.UTC()

	data, err := json.Marshal(paste)
	if err != nil {
		return fmt.Errorf("marshal paste: %w", err)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		pBucket := tx.Bucket(pasteBucket)
		eBucket := tx.Bucket(expireBucket)
		if pBucket == nil || eBucket == nil {
			return errors.New("buckets not initialized")
		}

		if existing := pBucket.Get([]byte(paste.ID)); existing != nil {
			var prev storage.Paste
			if err := json.Unmarshal(existing, &prev); err == nil && prev.HasExpiration() {
				if err := eBucket.Delete(expireKey(prev.ExpiresAt, prev.ID)); err != nil {
					return fmt.Errorf("remove previous expiry index: %w", err)
				}
			}
		}

		if err := pBucket.Put([]byte(paste.ID), data); err != nil {
			return fmt.Errorf("save paste: %w", err)
		}

		if paste.HasExpiration() {
			if err := eBucket.Put(expireKey(paste.ExpiresAt, paste.ID), []byte(paste.ID)); err != nil {
				return fmt.Errorf("index expiry: %w", err)
			}
		}

		return nil
	})
}

// Get retrieves a paste by id.
func (s *Store) Get(ctx context.Context, id string) (*storage.Paste, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	var out *storage.Paste
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(pasteBucket)
		if bucket == nil {
			return errors.New("pastes bucket missing")
		}
		raw := bucket.Get([]byte(id))
		if raw == nil {
			return storage.ErrNotFound
		}
		var paste storage.Paste
		if err := json.Unmarshal(raw, &paste); err != nil {
			return fmt.Errorf("unmarshal paste: %w", err)
		}
		out = &paste
		return nil
	})

	return out, err
}

// Delete removes a paste.
func (s *Store) Delete(ctx context.Context, id string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		pBucket := tx.Bucket(pasteBucket)
		eBucket := tx.Bucket(expireBucket)
		if pBucket == nil || eBucket == nil {
			return errors.New("buckets not initialized")
		}
		raw := pBucket.Get([]byte(id))
		if raw == nil {
			return storage.ErrNotFound
		}
		var paste storage.Paste
		if err := json.Unmarshal(raw, &paste); err == nil && paste.HasExpiration() {
			if err := eBucket.Delete(expireKey(paste.ExpiresAt, paste.ID)); err != nil {
				return fmt.Errorf("delete expiry index: %w", err)
			}
		}
		if err := pBucket.Delete([]byte(id)); err != nil {
			return fmt.Errorf("delete paste: %w", err)
		}
		return nil
	})
}

// DeleteExpired removes all pastes with expiry before or equal to the provided time.
func (s *Store) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	before = before.UTC()
	var removed int
	err := s.db.Update(func(tx *bolt.Tx) error {
		pBucket := tx.Bucket(pasteBucket)
		eBucket := tx.Bucket(expireBucket)
		if pBucket == nil || eBucket == nil {
			return errors.New("buckets not initialized")
		}

		cursor := eBucket.Cursor()
		cutoff := toTimestamp(before)
		for key, val := cursor.First(); key != nil; key, val = cursor.Next() {
			ts := binary.BigEndian.Uint64(key[:8])
			if ts > cutoff {
				break
			}
			id := string(val)
			if err := pBucket.Delete([]byte(id)); err != nil {
				return fmt.Errorf("delete expired paste %s: %w", id, err)
			}
			if err := cursor.Delete(); err != nil {
				return fmt.Errorf("delete expiry index: %w", err)
			}
			removed++
		}
		return nil
	})

	return removed, err
}

// Close closes the underlying database.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func expireKey(t time.Time, id string) []byte {
	key := make([]byte, 8+len(id))
	binary.BigEndian.PutUint64(key, toTimestamp(t))
	copy(key[8:], id)
	return key
}

func toTimestamp(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64(t.UTC().UnixNano())
}
