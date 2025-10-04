package httpserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"tiny-pastebin/internal/id"
)

func TestEndToEndCreateViewRaw(t *testing.T) {
	store := newMemoryStore()
	srv, err := New(Config{
		Store:       store,
		IDGenerator: id.New(12),
		MaxBytes:    1024,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	form := url.Values{}
	form.Set("content", "hello world")
	form.Set("syntax", "plaintext")
	form.Set("expire", "10m")

	resp, err := client.PostForm(ts.URL+"/pastes", form)
	if err != nil {
		t.Fatalf("post form: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatalf("missing location header")
	}

	viewResp, err := client.Get(ts.URL + loc)
	if err != nil {
		t.Fatalf("get view: %v", err)
	}
	body, err := io.ReadAll(viewResp.Body)
	viewResp.Body.Close()
	if err != nil {
		t.Fatalf("read view: %v", err)
	}
	if viewResp.StatusCode != http.StatusOK {
		t.Fatalf("view status %d", viewResp.StatusCode)
	}
	if !containsString(string(body), "hello world") {
		t.Fatalf("view missing content")
	}

	rawResp, err := client.Get(ts.URL + loc + "/raw")
	if err != nil {
		t.Fatalf("get raw: %v", err)
	}
	rawBody, err := io.ReadAll(rawResp.Body)
	rawResp.Body.Close()
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if rawResp.StatusCode != http.StatusOK {
		t.Fatalf("raw status %d", rawResp.StatusCode)
	}
	if string(rawBody) != "hello world" {
		t.Fatalf("raw body mismatch")
	}
}

func containsString(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
