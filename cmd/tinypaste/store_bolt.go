package main

import (
	"tiny-pastebin/internal/storage"
	"tiny-pastebin/internal/storage/boltstore"
)

func openStore(path string) (storage.Store, error) {
	return boltstore.Open(path)
}
