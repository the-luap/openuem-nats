package tasksecrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

const ownedKey = "0123456789abcdef0123456789abcdef"

func TestSSHStorageRoundTripAndMigration(t *testing.T) {
	for _, value := range []string{"", "aabb", "Owned SSH passphrase 🗝", sshPrefix + "literal input", strings.Repeat("x", MaxPlainSize)} {
		sealed, err := SealSSH(value, ownedKey)
		if err != nil {
			t.Fatal(err)
		}
		if value != "" && (sealed == value || !strings.HasPrefix(sealed, sshPrefix)) {
			t.Fatal("secret was not sealed")
		}
		plain, err := OpenSSH(sealed, ownedKey)
		if err != nil || plain != value {
			t.Fatal("SSH round trip failed")
		}
		again, changed, err := MigrateSSH(sealed, ownedKey)
		if err != nil || changed || again != sealed {
			t.Fatal("migration changed sealed data")
		}
		second, err := SealSSH(value, ownedKey)
		if err != nil || (value != "" && second == sealed) {
			t.Fatal("nonce was reused")
		}
	}
	legacy := "Owned legacy passphrase"
	migrated, changed, err := MigrateSSH(legacy, ownedKey)
	if err != nil || !changed || migrated == legacy {
		t.Fatal("legacy migration failed")
	}
	plain, err := OpenSSH(migrated, ownedKey)
	if err != nil || plain != legacy {
		t.Fatal("migrated value changed")
	}
	plain, err = OpenSSH(legacy, "")
	if err != nil || plain != legacy {
		t.Fatal("legacy reader compatibility failed")
	}
}

func TestSSHRejectsInvalidValuesWithoutDisclosure(t *testing.T) {
	sealed, err := SealSSH("Owned SSH test secret", ownedKey)
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(sealed)
	tampered[len(sshPrefix)+2] ^= 1
	for _, input := range []struct{ value, key string }{
		{sealed, ""}, {sealed, strings.Repeat("k", 32)}, {string(tampered), ownedKey},
		{sshPrefix, ownedKey}, {sshPrefix + "YWJj", ownedKey}, {Prefix + "ssh:v2:abc", ownedKey},
		{Prefix + "password:v1:abc", ownedKey}, {sealed + "\n", ownedKey},
		{strings.Repeat("x", MaxSSHStoredSize+1), ownedKey}, {strings.Repeat("x", MaxPlainSize+1), ownedKey},
		{"\xff", ownedKey}, {"owned\x00secret", ownedKey},
	} {
		plain, err := OpenSSH(input.value, input.key)
		if err != ErrUnavailable || plain != "" {
			t.Fatal("invalid SSH value did not fail closed")
		}
		_, changed, err := MigrateSSH(input.value, input.key)
		if err != ErrUnavailable || changed {
			t.Fatal("invalid value was migrated")
		}
	}
	for _, value := range []string{"owned", "\xff", "owned\x00secret", strings.Repeat("x", MaxPlainSize+1)} {
		if sealed, err := SealSSH(value, "invalid-key"); err != ErrUnavailable || sealed != "" {
			t.Fatal("invalid secret or key was accepted")
		}
	}
}

// Construct a vector independently of sshCipher using RFC 5869's two HMAC
// steps, a fixed nonce, and explicit AAD. This locks the cross-service contract.
func TestSSHEnvelopeContract(t *testing.T) {
	extract := hmac.New(sha256.New, make([]byte, sha256.Size))
	extract.Write([]byte(ownedKey))
	expand := hmac.New(sha256.New, extract.Sum(nil))
	expand.Write([]byte("openuem:task-secret:ssh:v1:\x01"))
	block, err := aes.NewCipher(expand.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("ownednonce12")
	envelope := "openuem:task-secret:ssh:v1:" + base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte("owned fixture"), []byte("openuem:task-secret:ssh:v1:")))
	plain, err := OpenSSH(envelope, ownedKey)
	if err != nil || plain != "owned fixture" {
		t.Fatal("version-one envelope contract changed")
	}
}

func TestPasswordLegacyCompatibilityAndFailure(t *testing.T) {
	for _, value := range []string{"", "a", "aabb", strings.Repeat("a", 54), "Owned nonhex password", strings.Repeat("x", MaxPlainSize)} {
		legacy, err := OpenPassword(value, "")
		if err != nil || legacy != value {
			t.Fatal("legacy plaintext failed")
		}
		stored, changed, err := MigratePassword(value, ownedKey)
		if err != nil || changed != (value != "") {
			t.Fatal("password migration failed")
		}
		plain, err := OpenPassword(stored, ownedKey)
		if err != nil || plain != value {
			t.Fatal("password round trip failed")
		}
		again, changed, err := MigratePassword(stored, ownedKey)
		if err != nil || changed || again != stored {
			t.Fatal("password migration was not idempotent")
		}
		if value != "" {
			plain, err := OpenPassword(stored, strings.Repeat("k", 32))
			if err != ErrUnavailable || plain != "" {
				t.Fatal("wrong key exposed password")
			}
		}
	}
	for _, value := range []string{strings.Repeat("a", 56), strings.Repeat("a", MaxPasswordStoredSize+2), strings.Repeat("x", MaxPlainSize+1), "owned\x00secret", "\xff"} {
		if plain, err := OpenPassword(value, ownedKey); err != ErrUnavailable || plain != "" {
			t.Fatal("invalid password was accepted")
		}
		if _, changed, err := MigratePassword(value, ownedKey); err != ErrUnavailable || changed {
			t.Fatal("invalid password was migrated")
		}
	}
}

func FuzzSecretDecoders(f *testing.F) {
	for _, value := range []string{"", "aabb", "Owned", sshPrefix, strings.Repeat("a", 56)} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if _, err := OpenSSH(value, ownedKey); err != nil && err != ErrUnavailable {
			t.Fatal("unexpected SSH error")
		}
		if _, err := OpenPassword(value, ownedKey); err != nil && err != ErrUnavailable {
			t.Fatal("unexpected password error")
		}
	})
}
