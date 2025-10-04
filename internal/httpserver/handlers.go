package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/skip2/go-qrcode"

	"tiny-pastebin/internal/security"
	"tiny-pastebin/internal/storage"
)

var (
	syntaxWhitelist = []string{"plaintext", "go", "python", "js", "ts", "c", "cpp", "java", "bash", "sql", "html", "css", "json", "yaml", "markdown"}
	syntaxLabels    = map[string]string{
		"plaintext": "Plain Text",
		"go":        "Go",
		"python":    "Python",
		"js":        "JavaScript",
		"ts":        "TypeScript",
		"c":         "C",
		"cpp":       "C++",
		"java":      "Java",
		"bash":      "Bash",
		"sql":       "SQL",
		"html":      "HTML",
		"css":       "CSS",
		"json":      "JSON",
		"yaml":      "YAML",
		"markdown":  "Markdown",
	}
	expireChoices = []expireOption{
		{Value: "10m", Label: "10 minutes", Duration: 10 * time.Minute},
		{Value: "1h", Label: "1 hour", Duration: time.Hour},
		{Value: "1d", Label: "1 day", Duration: 24 * time.Hour},
		{Value: "7d", Label: "7 days", Duration: 7 * 24 * time.Hour},
		{Value: "never", Label: "Never", Duration: 0},
	}
	expireMap = func() map[string]time.Duration {
		m := make(map[string]time.Duration, len(expireChoices))
		for _, c := range expireChoices {
			m[c.Value] = c.Duration
		}
		return m
	}()
)

const defaultExpire = "7d"

type expireOption struct {
	Value    string
	Label    string
	Duration time.Duration
}

type option struct {
	Value    string
	Label    string
	Selected bool
}

type indexPageData struct {
	SyntaxOptions []option
	ExpireOptions []option
	Content       string
	Syntax        string
	Expire        string
	Error         string
	MaxBytes      int
}

type viewPageData struct {
	Paste       *storage.Paste
	SyntaxLabel string
	ExpiresIn   string
	Canonical   string
}

type passwordPageData struct {
	ID    string
	Error string
}

type errorPageData struct {
	Message string
}

type titled interface {
	PageTitle() string
}

func (d indexPageData) PageTitle() string {
	return "New Paste · Tiny Pastebin"
}

func (d viewPageData) PageTitle() string {
	if d.Paste != nil && d.Paste.ID != "" {
		return fmt.Sprintf("%s · Tiny Pastebin", d.Paste.ID)
	}
	return "View Paste · Tiny Pastebin"
}

func (d passwordPageData) PageTitle() string {
	return "Protected Paste · Tiny Pastebin"
}

func (d errorPageData) PageTitle() string {
	if d.Message == "" {
		return "Tiny Pastebin"
	}
	return d.Message + " · Tiny Pastebin"
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data := s.indexData("", defaultExpire, "", "")
	s.render(w, r, http.StatusOK, "index", data)
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	maxBody := int64(s.maxBytes) + 4096
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		s.render(w, r, http.StatusBadRequest, "index", s.indexData("", defaultExpire, "", "Unable to parse form"))
		return
	}

	content := r.FormValue("content")
	syntax := r.FormValue("syntax")
	expire := r.FormValue("expire")
	password := r.FormValue("password")

	if expire == "" {
		expire = defaultExpire
	}

	contentSize := len([]byte(content))
	if contentSize == 0 {
		s.render(w, r, http.StatusBadRequest, "index", s.indexData(syntax, expire, content, "Content cannot be empty"))
		return
	}
	if contentSize > s.maxBytes {
		s.render(w, r, http.StatusBadRequest, "index", s.indexData(syntax, expire, content, fmt.Sprintf("Content exceeds %d byte limit", s.maxBytes)))
		return
	}

	if !isAllowedSyntax(syntax) {
		s.render(w, r, http.StatusBadRequest, "index", s.indexData(syntax, expire, content, "Unsupported syntax"))
		return
	}

	duration, ok := expireMap[expire]
	if !ok {
		s.render(w, r, http.StatusBadRequest, "index", s.indexData(syntax, expire, content, "Invalid expiration"))
		return
	}

	hashed := ""
	if strings.TrimSpace(password) != "" {
		var err error
		hashed, err = security.HashPassword(password)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
	}

	id, err := s.idGen.Generate(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	now := s.nowTime().UTC()
	paste := &storage.Paste{
		ID:           id,
		Content:      content,
		Syntax:       syntax,
		CreatedAt:    now,
		PasswordHash: hashed,
		Size:         contentSize,
	}
	if duration > 0 {
		paste.ExpiresAt = now.Add(duration)
	}

	if err := s.store.Save(r.Context(), paste); err != nil {
		s.serverError(w, r, err)
		return
	}

	http.Redirect(w, r, "/p/"+id, http.StatusSeeOther)
}

func (s *Server) handleView(w http.ResponseWriter, r *http.Request) {
	paste, err := s.fetchPaste(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			s.notFound(w, r)
			return
		}
		s.serverError(w, r, err)
		return
	}

	if paste.PasswordHash != "" && !s.hasAuth(r, paste.ID) {
		s.render(w, r, http.StatusOK, "password", passwordPageData{ID: paste.ID})
		return
	}

	data := viewPageData{
		Paste:       paste,
		SyntaxLabel: syntaxLabel(paste.Syntax),
		ExpiresIn:   remaining(paste.ExpiresAt, s.nowTime()),
		Canonical:   s.canonicalURL(r, paste.ID),
	}
	s.render(w, r, http.StatusOK, "view", data)
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.render(w, r, http.StatusBadRequest, "password", passwordPageData{ID: chi.URLParam(r, "id"), Error: "Unable to parse form"})
		return
	}
	id := chi.URLParam(r, "id")
	paste, err := s.fetchPaste(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			s.notFound(w, r)
			return
		}
		s.serverError(w, r, err)
		return
	}
	if paste.PasswordHash == "" {
		http.Redirect(w, r, "/p/"+id, http.StatusSeeOther)
		return
	}
	password := r.FormValue("password")
	ok, err := security.VerifyPassword(paste.PasswordHash, password)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		s.render(w, r, http.StatusUnauthorized, "password", passwordPageData{ID: id, Error: "Incorrect password"})
		return
	}

	s.setAuthCookie(w, r, id, paste.ExpiresAt)
	http.Redirect(w, r, "/p/"+id, http.StatusSeeOther)
}

func (s *Server) handleRaw(w http.ResponseWriter, r *http.Request) {
	paste, err := s.fetchPaste(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			s.notFound(w, r)
			return
		}
		s.serverError(w, r, err)
		return
	}

	if paste.PasswordHash != "" && !s.hasAuth(r, paste.ID) {
		s.notFound(w, r)
		return
	}

	etag := etagFor(paste.Content)
	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "private, max-age=60")
	w.Header().Set("ETag", etag)
	_, _ = io.WriteString(w, paste.Content)
}

func (s *Server) handleQR(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	paste, err := s.fetchPaste(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			s.notFound(w, r)
			return
		}
		s.serverError(w, r, err)
		return
	}
	if paste.PasswordHash != "" && !s.hasAuth(r, paste.ID) {
		s.notFound(w, r)
		return
	}

	png, err := qrcode.Encode(s.canonicalURL(r, id), qrcode.Medium, 256)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

func (s *Server) fetchPaste(ctx context.Context, id string) (*storage.Paste, error) {
	paste, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if paste == nil {
		return nil, storage.ErrNotFound
	}
	if paste.ExpiresAt.IsZero() {
		return paste, nil
	}
	if s.nowTime().After(paste.ExpiresAt) {
		return nil, storage.ErrNotFound
	}
	return paste, nil
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, data any) {
	title := "Tiny Pastebin"
	if t, ok := data.(titled); ok {
		if pt := t.PageTitle(); pt != "" {
			title = pt
		}
	}
	body := &bytes.Buffer{}
	bodyTemplate := name + "-body"
	if err := s.templates.ExecuteTemplate(body, bodyTemplate, data); err != nil {
		s.handleTemplateError(w, status, bodyTemplate, err)
		return
	}
	layoutBuf := &bytes.Buffer{}
	layoutData := struct {
		Title string
		Body  template.HTML
	}{
		Title: title,
		Body:  template.HTML(body.String()),
	}
	if err := s.templates.ExecuteTemplate(layoutBuf, "layout", layoutData); err != nil {
		s.handleTemplateError(w, status, "layout", err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = layoutBuf.WriteTo(w)
}

func (s *Server) handleTemplateError(w http.ResponseWriter, status int, name string, err error) {
	if s.logger != nil {
		s.logger.Error("render template", "error", err, "template", name)
	}
	http.Error(w, "Template error", status)
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	if s.logger != nil {
		s.logger.Error("internal error", "error", err)
	}
	s.render(w, r, http.StatusInternalServerError, "error", errorPageData{Message: "Internal server error"})
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusNotFound, "error", errorPageData{Message: "Not found or expired"})
}

func (s *Server) indexData(selectedSyntax, selectedExpire, content, errMsg string) indexPageData {
	if selectedSyntax == "" {
		selectedSyntax = "plaintext"
	}
	if !isAllowedSyntax(selectedSyntax) {
		selectedSyntax = "plaintext"
	}
	if selectedExpire == "" {
		selectedExpire = defaultExpire
	}
	synOpts := make([]option, 0, len(syntaxWhitelist))
	for _, v := range syntaxWhitelist {
		synOpts = append(synOpts, option{
			Value:    v,
			Label:    syntaxLabel(v),
			Selected: v == selectedSyntax,
		})
	}
	expOpts := make([]option, 0, len(expireChoices))
	for _, c := range expireChoices {
		expOpts = append(expOpts, option{
			Value:    c.Value,
			Label:    c.Label,
			Selected: c.Value == selectedExpire,
		})
	}
	return indexPageData{
		SyntaxOptions: synOpts,
		ExpireOptions: expOpts,
		Content:       content,
		Syntax:        selectedSyntax,
		Expire:        selectedExpire,
		Error:         errMsg,
		MaxBytes:      s.maxBytes,
	}
}

func isAllowedSyntax(v string) bool {
	_, ok := syntaxLabels[v]
	return ok
}

func syntaxLabel(v string) string {
	if label, ok := syntaxLabels[v]; ok {
		return label
	}
	if v == "" {
		return "Plain Text"
	}
	return strings.ToUpper(v[:1]) + v[1:]
}

func remaining(expires time.Time, now time.Time) string {
	if expires.IsZero() {
		return "Never"
	}
	if now.After(expires) {
		return "Expired"
	}
	dur := expires.Sub(now)
	if dur < time.Second {
		return "Less than a second"
	}
	units := []struct {
		d    time.Duration
		name string
	}{
		{time.Hour * 24, "day"},
		{time.Hour, "hour"},
		{time.Minute, "minute"},
	}
	parts := make([]string, 0, len(units))
	for _, u := range units {
		if dur >= u.d {
			count := dur / u.d
			parts = append(parts, plural(int(count), u.name))
			dur -= count * u.d
		}
	}
	if len(parts) == 0 {
		seconds := int(dur.Seconds())
		if seconds <= 1 {
			return "1 second"
		}
		return fmt.Sprintf("%d seconds", seconds)
	}
	return strings.Join(parts, ", ")
}

func plural(count int, singular string) string {
	if count == 1 {
		return fmt.Sprintf("1 %s", singular)
	}
	return fmt.Sprintf("%d %ss", count, singular)
}

func etagFor(content string) string {
	sum := sha256.Sum256([]byte(content))
	return `"` + hex.EncodeToString(sum[:]) + `"`
}
