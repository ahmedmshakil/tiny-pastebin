package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 1
	argonKeyLen  = 32
	saltLen      = 16
)

// HashPassword hashes the provided password using Argon2id.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", nil
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return encodeHash(salt, hash), nil
}

// VerifyPassword checks whether the provided password matches the stored hash.
func VerifyPassword(encoded, password string) (bool, error) {
	if encoded == "" {
		return password == "", nil
	}
	params, salt, expected, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	hash := argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, uint32(len(expected)))
	if subtle.ConstantTimeCompare(hash, expected) == 1 {
		return true, nil
	}
	return false, nil
}

type argonParams struct {
	time    uint32
	memory  uint32
	threads uint8
}

func encodeHash(salt, hash []byte) string {
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads, b64Salt, b64Hash)
}

func decodeHash(encoded string) (argonParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return argonParams{}, nil, nil, errors.New("invalid hash format")
	}
	if parts[1] != "argon2id" {
		return argonParams{}, nil, nil, errors.New("invalid algorithm")
	}
	var (
		params    argonParams
		memTmp    int
		timeTmp   int
		threadTmp int
	)
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memTmp, &timeTmp, &threadTmp); err != nil {
		return argonParams{}, nil, nil, fmt.Errorf("parse params: %w", err)
	}
	if memTmp <= 0 || timeTmp <= 0 || threadTmp <= 0 {
		return argonParams{}, nil, nil, errors.New("invalid argon params")
	}
	params.memory = uint32(memTmp)
	params.time = uint32(timeTmp)
	if threadTmp > 255 {
		return argonParams{}, nil, nil, errors.New("argon threads out of range")
	}
	params.threads = uint8(threadTmp)
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argonParams{}, nil, nil, fmt.Errorf("decode salt: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argonParams{}, nil, nil, fmt.Errorf("decode hash: %w", err)
	}
	return params, salt, hash, nil
}
