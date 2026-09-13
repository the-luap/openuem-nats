// Package tasksecrets shares the console and worker storage contract for local
// account task secrets. It never logs keys, stored values or decrypted values.
package tasksecrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf8"
)

const (
	MaxPlainSize = 16 << 10
	// Prefix is reserved for authenticated task-secret envelopes, including future versions.
	Prefix                = "openuem:task-secret:"
	sshPrefix             = Prefix + "ssh:v1:"
	MaxSSHStoredSize      = len(sshPrefix) + (MaxPlainSize+28)*4/3 + 1
	MaxPasswordStoredSize = (MaxPlainSize + 28) * 2
)

var ErrUnavailable = errors.New("task secret is unavailable")

func validPlain(value string) bool {
	return len(value) <= MaxPlainSize && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

func sshCipher(masterKey string) (cipher.AEAD, error) {
	if len(masterKey) != 32 {
		return nil, ErrUnavailable
	}
	key, err := hkdf.Key(sha256.New, []byte(masterKey), nil, sshPrefix, 32)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrUnavailable
	}
	return cipher.NewGCM(block)
}

// SealSSH always treats its input as plaintext, even when it resembles an
// envelope. Empty values remain empty. A fresh nonce protects each replacement.
func SealSSH(value, masterKey string) (string, error) {
	if !validPlain(value) {
		return "", ErrUnavailable
	}
	if value == "" {
		return "", nil
	}
	aead, err := sshCipher(masterKey)
	if err != nil {
		return "", ErrUnavailable
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", ErrUnavailable
	}
	plain := []byte(value)
	defer clear(plain)
	sealed := aead.Seal(nonce, nonce, plain, []byte(sshPrefix))
	return sshPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// OpenSSH accepts unmarked legacy plaintext during a coordinated upgrade.
// Reserved-prefix values must authenticate; malformed or unknown versions never
// fall back to plaintext. Field-level binding deliberately permits task clones.
func OpenSSH(value, masterKey string) (string, error) {
	if len(value) > MaxSSHStoredSize {
		return "", ErrUnavailable
	}
	if !strings.HasPrefix(value, Prefix) {
		if !validPlain(value) {
			return "", ErrUnavailable
		}
		return value, nil
	}
	if !strings.HasPrefix(value, sshPrefix) {
		return "", ErrUnavailable
	}
	encoded := strings.TrimPrefix(value, sshPrefix)
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(data) < 28 || base64.RawURLEncoding.EncodeToString(data) != encoded {
		return "", ErrUnavailable
	}
	aead, err := sshCipher(masterKey)
	if err != nil {
		return "", ErrUnavailable
	}
	plain, err := aead.Open(nil, data[:12], data[12:], []byte(sshPrefix))
	if err != nil {
		return "", ErrUnavailable
	}
	defer clear(plain)
	result := string(plain)
	if !validPlain(result) {
		return "", ErrUnavailable
	}
	return result, nil
}

// MigrateSSH verifies existing envelopes and encrypts only unmarked nonempty
// legacy values. It returns unchanged ciphertext on repeated migrations.
func MigrateSSH(value, masterKey string) (string, bool, error) {
	if _, err := OpenSSH(value, masterKey); err != nil {
		return "", false, err
	}
	if value == "" || strings.HasPrefix(value, Prefix) {
		return value, false, nil
	}
	sealed, err := SealSSH(value, masterKey)
	return sealed, err == nil, err
}

// OpenPassword reads the historical nonce+ciphertext hexadecimal format. That
// format has no marker: long hexadecimal input must authenticate, while short
// hex plaintext must never reach a nonce slice. Ambiguous legacy values require
// explicit replacement by the administrator, not a plaintext fallback.
func OpenPassword(value, masterKey string) (string, error) {
	if len(value) > MaxPasswordStoredSize {
		return "", ErrUnavailable
	}
	data, err := hex.DecodeString(value)
	if err != nil || len(data) < 28 {
		if !validPlain(value) {
			return "", ErrUnavailable
		}
		return value, nil
	}
	block, err := aes.NewCipher([]byte(masterKey))
	if err != nil {
		return "", ErrUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrUnavailable
	}
	plain, err := aead.Open(nil, data[:12], data[12:], nil)
	if err != nil {
		return "", ErrUnavailable
	}
	defer clear(plain)
	result := string(plain)
	if !validPlain(result) {
		return "", ErrUnavailable
	}
	return result, nil
}

// SealPassword preserves the existing password wire/storage contract. New
// SSH passphrases use the versioned, purpose-bound envelope instead.
func SealPassword(value, masterKey string) (string, error) {
	if !validPlain(value) {
		return "", ErrUnavailable
	}
	if value == "" {
		return "", nil
	}
	block, err := aes.NewCipher([]byte(masterKey))
	if err != nil {
		return "", ErrUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrUnavailable
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", ErrUnavailable
	}
	plain := []byte(value)
	defer clear(plain)
	return hex.EncodeToString(aead.Seal(nonce, nonce, plain, nil)), nil
}

func MigratePassword(value, masterKey string) (string, bool, error) {
	if _, err := OpenPassword(value, masterKey); err != nil {
		return "", false, err
	}
	data, err := hex.DecodeString(value)
	if value == "" || (err == nil && len(data) >= 28) {
		return value, false, nil
	}
	sealed, err := SealPassword(value, masterKey)
	return sealed, err == nil, err
}
