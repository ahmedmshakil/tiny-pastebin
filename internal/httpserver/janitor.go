package httpserver

import (
	"context"
	"log/slog"
	"time"

	"tiny-pastebin/internal/storage"
)

// StartJanitor launches a background janitor that deletes expired pastes.
func StartJanitor(ctx context.Context, store storage.Store, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanOnce(ctx, store, logger)
			}
		}
	}()
}

func cleanOnce(ctx context.Context, store storage.Store, logger *slog.Logger) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	removed, err := store.DeleteExpired(c, time.Now())
	if err != nil {
		if logger != nil {
			logger.Error("janitor error", "error", err)
		}
		return
	}
	if removed > 0 && logger != nil {
		logger.Info("janitor removed expired pastes", "count", removed)
	}
}
