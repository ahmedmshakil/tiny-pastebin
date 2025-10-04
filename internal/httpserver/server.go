package httpserver

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"tiny-pastebin/internal/id"
	"tiny-pastebin/internal/storage"
	"tiny-pastebin/web"
)

// Config captures server configuration.
type Config struct {
	Store        storage.Store
	IDGenerator  *id.Generator
	MaxBytes     int
	RateLimiter  *RateLimiter
	TrustProxy   bool
	BaseURL      string
	Logger       *slog.Logger
	CookieSecret []byte
}

// Server wraps HTTP handling logic.
type Server struct {
	store        storage.Store
	idGen        *id.Generator
	router       chi.Router
	templates    *template.Template
	maxBytes     int
	limiter      *RateLimiter
	trustProxy   bool
	baseURL      *url.URL
	logger       *slog.Logger
	cookieSecret []byte
	now          func() time.Time
}

// New constructs a new Server instance.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("store required")
	}
	if cfg.IDGenerator == nil {
		cfg.IDGenerator = id.New(0)
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 1_048_576
	}
	tmpl, err := template.New("layout").Funcs(template.FuncMap{
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return "Never"
			}
			return t.Local().Format(time.RFC1123)
		},
		"formatSize": func(size int) string {
			if size < 1024 {
				return fmt.Sprintf("%d B", size)
			}
			const unit = 1024.0
			kb := float64(size)
			for _, suffix := range []string{"KB", "MB", "GB"} {
				kb /= unit
				if kb < unit {
					return fmt.Sprintf("%.1f %s", kb, suffix)
				}
			}
			return fmt.Sprintf("%d B", size)
		},
	}).ParseFS(web.Templates, "templates/*.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	var parsedBase *url.URL
	if cfg.BaseURL != "" {
		parsedBase, err = url.Parse(cfg.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("invalid base url: %w", err)
		}
		if parsedBase.Scheme == "" || parsedBase.Host == "" {
			return nil, errors.New("base url must include scheme and host")
		}
		parsedBase.Path = strings.TrimSuffix(parsedBase.Path, "/")
	}

	secret := cfg.CookieSecret
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("generate cookie secret: %w", err)
		}
	}

	srv := &Server{
		store:        cfg.Store,
		idGen:        cfg.IDGenerator,
		router:       chi.NewRouter(),
		templates:    tmpl,
		maxBytes:     cfg.MaxBytes,
		limiter:      cfg.RateLimiter,
		trustProxy:   cfg.TrustProxy,
		baseURL:      parsedBase,
		logger:       cfg.Logger,
		cookieSecret: secret,
		now:          time.Now,
	}
	srv.routes()
	return srv, nil
}

// Handler returns the underlying router.
func (s *Server) Handler() http.Handler {
	return s.router
}

func (s *Server) routes() {
	r := s.router

	r.Use(middleware.RequestID)
	if s.trustProxy {
		r.Use(middleware.RealIP)
	}
	r.Use(RateLimitMiddleware(s.limiter, func(r *http.Request) string {
		return ClientIP(r, s.trustProxy)
	}))
	r.Use(middleware.Compress(5, "text/html", "text/plain", "application/javascript", "text/css"))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Logger)

	fileServer := http.FileServer(http.FS(web.Static))
	r.Handle("/static/*", http.StripPrefix("/static/", fileServer))
	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		data, err := web.Static.ReadFile("static/favicon.ico")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write(data)
	})

	r.Get("/", s.handleIndex)
	r.Post("/pastes", s.handleCreate)

	r.Route("/p/{id}", func(pr chi.Router) {
		pr.Get("/", s.handleView)
		pr.Post("/", s.handlePassword)
		pr.Get("/raw", s.handleRaw)
		pr.Get("/qr", s.handleQR)
	})

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func (s *Server) authCookieName(id string) string {
	return fmt.Sprintf("auth_%s", id)
}

func (s *Server) signValue(id string) string {
	mac := hmac.New(sha256.New, s.cookieSecret)
	mac.Write([]byte(id))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) verifySignature(id, sig string) bool {
	expected := s.signValue(id)
	if len(expected) != len(sig) {
		return false
	}
	return hmac.Equal([]byte(expected), []byte(sig))
}

func (s *Server) setAuthCookie(w http.ResponseWriter, r *http.Request, id string, expires time.Time) {
	cookie := &http.Cookie{
		Name:     s.authCookieName(id),
		Value:    s.signValue(id),
		Path:     "/p/" + id,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.isSecureRequest(r),
	}
	if !expires.IsZero() {
		cookie.Expires = expires
		remaining := time.Until(expires)
		if remaining > 0 {
			cookie.MaxAge = int(remaining.Seconds())
		}
	}
	http.SetCookie(w, cookie)
}

func (s *Server) hasAuth(r *http.Request, id string) bool {
	cookie, err := r.Cookie(s.authCookieName(id))
	if err != nil {
		return false
	}
	return s.verifySignature(id, cookie.Value)
}

func (s *Server) clearAuthCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.authCookieName(id),
		Value:    "",
		Path:     "/p/" + id,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if s.baseURL != nil && s.baseURL.Scheme == "https" {
		return true
	}
	if s.trustProxy {
		proto := strings.ToLower(r.Header.Get("X-Forwarded-Proto"))
		if proto == "https" {
			return true
		}
	}
	return false
}

func (s *Server) canonicalURL(r *http.Request, id string) string {
	if s.baseURL != nil {
		u := *s.baseURL
		if id != "" {
			u.Path = strings.TrimSuffix(u.Path, "/") + "/p/" + id
		}
		return u.String()
	}

	scheme := "http"
	if s.isSecureRequest(r) {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost"
	}
	path := "/"
	if id != "" {
		path = "/p/" + id
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, path)
}

func (s *Server) nowTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}
