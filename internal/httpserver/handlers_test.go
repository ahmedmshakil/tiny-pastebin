package httpserver

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"tiny-pastebin/internal/id"
	"tiny-pastebin/internal/security"
	"tiny-pastebin/internal/storage"
)

type memoryStore struct {
	mu     sync.RWMutex
	pastes map[string]*storage.Paste
}

func newMemoryStore() *memoryStore {
	return &memoryStore{pastes: make(map[string]*storage.Paste)}
}

func (m *memoryStore) Save(ctx context.Context, paste *storage.Paste) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *paste
	m.pastes[paste.ID] = &cp
	return nil
}

func (m *memoryStore) Get(ctx context.Context, id string) (*storage.Paste, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.pastes[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := *p
	return &cp, nil
}

func (m *memoryStore) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.pastes[id]; !ok {
		return storage.ErrNotFound
	}
	delete(m.pastes, id)
	return nil
}

func (m *memoryStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for id, paste := range m.pastes {
		if paste.ExpiresAt.IsZero() {
			continue
		}
		if !paste.ExpiresAt.After(before) {
			delete(m.pastes, id)
			removed++
		}
	}
	return removed, nil
}

func (m *memoryStore) Close() error { return nil }

func TestCreateViewRawFlow(t *testing.T) {
	store := newMemoryStore()
	srv, err := New(Config{
		Store:       store,
		IDGenerator: id.New(12),
		MaxBytes:    1024,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	form := url.Values{}
	form.Set("content", "package main\nfunc main() {}")
	form.Set("syntax", "go")
	form.Set("expire", "7d")

	req := httptest.NewRequest(http.MethodPost, "/pastes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc == "" {
		t.Fatalf("missing redirect location")
	}

	// View page
	viewReq := httptest.NewRequest(http.MethodGet, loc, nil)
	viewRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(viewRec, viewReq)
	if viewRec.Code != http.StatusOK {
		t.Fatalf("view status: %d", viewRec.Code)
	}
	if !strings.Contains(viewRec.Body.String(), "package main") {
		t.Fatalf("view response missing content")
	}

	rawReq := httptest.NewRequest(http.MethodGet, loc+"/raw", nil)
	rawRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rawRec, rawReq)
	if rawRec.Code != http.StatusOK {
		t.Fatalf("raw status: %d", rawRec.Code)
	}
	body, _ := io.ReadAll(rawRec.Body)
	if !bytes.Contains(body, []byte("package main")) {
		t.Fatalf("raw body mismatch")
	}
}

func TestPasswordProtectedFlow(t *testing.T) {
	store := newMemoryStore()
	hashed, err := security.HashPassword("sekret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	paste := &storage.Paste{
		ID:           "pass1",
		Content:      "secret text",
		Syntax:       "plaintext",
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		PasswordHash: hashed,
		Size:         len("secret text"),
	}
	if err := store.Save(context.Background(), paste); err != nil {
		t.Fatalf("save paste: %v", err)
	}

	srv, err := New(Config{
		Store:       store,
		IDGenerator: id.New(12),
		MaxBytes:    1024,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	viewReq := httptest.NewRequest(http.MethodGet, "/p/pass1", nil)
	viewRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(viewRec, viewReq)
	if viewRec.Code != http.StatusOK {
		t.Fatalf("expected password form status 200 got %d", viewRec.Code)
	}
	if !strings.Contains(viewRec.Body.String(), "Enter password") {
		t.Fatalf("expected password prompt")
	}

	// Wrong password
	wrongForm := url.Values{"password": {"nope"}}
	wrongReq := httptest.NewRequest(http.MethodPost, "/p/pass1", strings.NewReader(wrongForm.Encode()))
	wrongReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wrongRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wrongRec, wrongReq)
	if wrongRec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password status %d", wrongRec.Code)
	}

	goodForm := url.Values{"password": {"sekret"}}
	goodReq := httptest.NewRequest(http.MethodPost, "/p/pass1", strings.NewReader(goodForm.Encode()))
	goodReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	goodRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(goodRec, goodReq)
	if goodRec.Code != http.StatusSeeOther {
		t.Fatalf("good password status %d", goodRec.Code)
	}
	resp := goodRec.Result()
	cookie := resp.Cookies()
	if len(cookie) == 0 {
		t.Fatalf("expected auth cookie, headers: %v", resp.Header)
	}

	rawReq := httptest.NewRequest(http.MethodGet, "/p/pass1/raw", nil)
	rawReq.AddCookie(cookie[0])
	rawRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rawRec, rawReq)
	if rawRec.Code != http.StatusOK {
		t.Fatalf("raw status %d", rawRec.Code)
	}
	if !strings.Contains(rawRec.Body.String(), "secret text") {
		t.Fatalf("raw body mismatch")
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	store := newMemoryStore()
	limiter := NewRateLimiter(rate.Limit(1), 1, time.Minute)
	srv, err := New(Config{
		Store:       store,
		IDGenerator: id.New(12),
		MaxBytes:    512,
		RateLimiter: limiter,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// First request allowed
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "1.2.3.4:1234"
	res1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res1, req1)
	if res1.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", res1.Code)
	}

	// Second immediate request should be limited
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "1.2.3.4:1234"
	res2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res2, req2)
	if res2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 got %d", res2.Code)
	}
}
