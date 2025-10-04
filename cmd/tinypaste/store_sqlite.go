//go:build sqlite

package main

import (
	"tiny-pastebin/internal/storage"
	"tiny-pastebin/internal/storage/sqlitestore"
)

func openStore(path string) (storage.Store, error) {
	return sqlitestore.Open(path)
}
