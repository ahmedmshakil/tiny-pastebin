package security

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if hash == "" {
		t.Fatalf("expected non-empty hash")
	}
	ok, err := VerifyPassword(hash, "secret")
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if !ok {
		t.Fatalf("expected password to verify")
	}
	ok, err = VerifyPassword(hash, "wrong")
	if err != nil {
		t.Fatalf("verify password wrong: %v", err)
	}
	if ok {
		t.Fatalf("expected mismatch")
	}
}

func TestVerifyEmpty(t *testing.T) {
	ok, err := VerifyPassword("", "")
	if err != nil {
		t.Fatalf("verify empty: %v", err)
	}
	if !ok {
		t.Fatalf("expected empty passwords to match")
	}
}
