package legacysecret

import (
	"strings"
	"testing"
)

func TestReplacementIsAlwaysLiteralAndBoundsAreEnforced(t *testing.T) {
	key := strings.Repeat("k", 32)
	original, err := Seal("owned-password", key)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := Seal(original, key)
	if err != nil || replacement == original {
		t.Fatal("ciphertext-like input bypassed replacement encryption")
	}
	plain, err := Open(replacement, key)
	if err != nil || plain != original {
		t.Fatal("replacement was not treated as literal plaintext")
	}
	for _, value := range []string{strings.Repeat("x", MaxPlainSize+1), "invalid\x00secret", "\xff"} {
		if stored, err := Seal(value, key); stored != "" || err != ErrUnavailable {
			t.Fatal("invalid plaintext accepted")
		}
	}
	for _, key := range []string{"", "invalid", strings.Repeat("z", 32)} {
		if plain, err := Open(original, key); plain != "" || err != ErrUnavailable {
			t.Fatal("invalid key disclosed a secret")
		}
	}
	for _, length := range []int{16, 24, 32} {
		key := strings.Repeat("k", length)
		stored, err := Seal("aabb", key)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := Open(stored, key)
		if err != nil || plain != "aabb" {
			t.Fatal("historical AES key size no longer works")
		}
	}
}
