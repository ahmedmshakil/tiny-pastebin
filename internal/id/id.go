package id

import (
	"context"

	gonanoid "github.com/matoous/go-nanoid/v2"
)

const defaultLength = 12

// Generator produces unique, URL-safe identifiers.
type Generator struct {
	length int
}

// New returns a Generator with the provided length. If length <= 0, a sane default is used.
func New(length int) *Generator {
	if length <= 0 {
		length = defaultLength
	}
	return &Generator{length: length}
}

// Generate returns a new identifier.
func (g *Generator) Generate(ctx context.Context) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}
	return gonanoid.New(g.length)
}
