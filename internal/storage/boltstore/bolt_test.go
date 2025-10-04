package boltstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"tiny-pastebin/internal/storage"
)

func TestStoreCRUD(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	paste := &storage.Paste{
		ID:        "abc123",
		Content:   "hello",
		Syntax:    "plaintext",
		CreatedAt: time.Now().UTC().Round(time.Second),
		Size:      5,
	}

	if err := store.Save(context.Background(), paste); err != nil {
		t.Fatalf("save paste: %v", err)
	}

	out, err := store.Get(context.Background(), "abc123")
	if err != nil {
		t.Fatalf("get paste: %v", err)
	}
	if out.Content != paste.Content {
		t.Fatalf("expected content %q got %q", paste.Content, out.Content)
	}

	if err := store.Delete(context.Background(), "abc123"); err != nil {
		t.Fatalf("delete paste: %v", err)
	}
	if _, err := store.Get(context.Background(), "abc123"); err == nil {
		t.Fatalf("expected not found")
	}
}

func TestDeleteExpired(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "exp.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	now := time.Now().UTC().Round(time.Second)
	active := &storage.Paste{ID: "alive", Content: "ok", Syntax: "plaintext", CreatedAt: now, Size: 2, ExpiresAt: now.Add(time.Hour)}
	expired := &storage.Paste{ID: "dead", Content: "bye", Syntax: "plaintext", CreatedAt: now, Size: 3, ExpiresAt: now.Add(-time.Minute)}

	if err := store.Save(context.Background(), active); err != nil {
		t.Fatalf("save active: %v", err)
	}
	if err := store.Save(context.Background(), expired); err != nil {
		t.Fatalf("save expired: %v", err)
	}

	removed, err := store.DeleteExpired(context.Background(), now)
	if err != nil {
		t.Fatalf("delete expired: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expected 1 removal, got %d", removed)
	}

	if _, err := store.Get(context.Background(), "dead"); err == nil {
		t.Fatalf("expected expired paste removed")
	}
	if _, err := store.Get(context.Background(), "alive"); err != nil {
		t.Fatalf("expected alive paste: %v", err)
	}
}
