package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"tiny-pastebin/internal/httpserver"
	"tiny-pastebin/internal/id"
)

func main() {
	cfg := parseFlags()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	store, err := openStore(cfg.dataPath)
	if err != nil {
		logger.Error("failed opening data store", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	limiter := httpserver.NewRateLimiter(rate.Limit(5), 10, 15*time.Minute)

	srv, err := httpserver.New(httpserver.Config{
		Store:       store,
		IDGenerator: id.New(12),
		MaxBytes:    cfg.maxBytes,
		RateLimiter: limiter,
		TrustProxy:  cfg.behindProxy,
		BaseURL:     cfg.baseURL,
		Logger:      logger,
	})
	if err != nil {
		logger.Error("failed to construct server", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	httpserver.StartJanitor(ctx, store, time.Minute, logger)

	srvHTTP := &http.Server{
		Addr:              cfg.addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.addr)
		if err := srvHTTP.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srvHTTP.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown error", "error", err)
		}
	case err := <-errCh:
		logger.Error("http server error", "error", err)
		os.Exit(1)
	}

	logger.Info("shutdown complete")
}

type config struct {
	addr        string
	dataPath    string
	baseURL     string
	maxBytes    int
	behindProxy bool
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.addr, "addr", ":8080", "listen address")
	flag.StringVar(&cfg.dataPath, "data", "./tiny-paste.db", "path to data file")
	flag.StringVar(&cfg.baseURL, "base-url", "", "canonical base URL (optional)")
	flag.IntVar(&cfg.maxBytes, "max-bytes", 1_048_576, "maximum paste size in bytes")
	flag.BoolVar(&cfg.behindProxy, "behind-proxy", false, "trust proxy headers for rate limiting and scheme")
	flag.Parse()

	if cfg.maxBytes <= 0 {
		fmt.Fprintf(os.Stderr, "max-bytes must be positive\n")
		os.Exit(2)
	}
	return cfg
}
