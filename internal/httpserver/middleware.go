package httpserver

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter implements a token bucket limiter per key.
type RateLimiter struct {
	rate    rate.Limit
	burst   int
	ttl     time.Duration
	mu      sync.Mutex
	clients map[string]*clientLimiter
}

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter constructs a RateLimiter.
func NewRateLimiter(r rate.Limit, burst int, ttl time.Duration) *RateLimiter {
	return &RateLimiter{
		rate:    r,
		burst:   burst,
		ttl:     ttl,
		clients: make(map[string]*clientLimiter),
	}
}

// Allow reports whether a request from key is permitted.
func (rl *RateLimiter) Allow(key string) bool {
	if rl == nil {
		return true
	}
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if key == "" {
		key = "unknown"
	}

	entry, ok := rl.clients[key]
	if !ok {
		entry = &clientLimiter{limiter: rate.NewLimiter(rl.rate, rl.burst)}
		rl.clients[key] = entry
	}
	entry.lastSeen = now
	allowed := entry.limiter.Allow()

	if len(rl.clients) > 0 && rl.ttl > 0 {
		for k, v := range rl.clients {
			if now.Sub(v.lastSeen) > rl.ttl {
				delete(rl.clients, k)
			}
		}
	}

	return allowed
}

// RateLimitMiddleware enforces the limiter per-client.
func RateLimitMiddleware(rl *RateLimiter, keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	if rl == nil {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := ""
			if keyFunc != nil {
				key = keyFunc(r)
			}
			if !rl.Allow(key) {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(http.StatusText(http.StatusTooManyRequests)))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ClientIP returns the client IP respecting proxy headers when trustProxy is true.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if len(parts) > 0 {
				ip := strings.TrimSpace(parts[0])
				if ip != "" {
					return ip
				}
			}
		}
		if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
			return strings.TrimSpace(xrip)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
