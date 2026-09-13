// Package legacysecret provides bounded, non-logging access to historical
// unmarked AES-GCM hex secrets. New formats should use purpose-bound envelopes.
package legacysecret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf8"
)

const MaxPlainSize = 16 << 10
const MaxStoredSize = (MaxPlainSize + 28) * 2

var ErrUnavailable = errors.New("stored secret is unavailable")

func validPlain(value string) bool {
	return len(value) <= MaxPlainSize && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

// Open reads the historical nonce+ciphertext hexadecimal format. That
// format has no marker: long hexadecimal input must authenticate, while short
// hex plaintext must never reach a nonce slice. Ambiguous legacy values require
// explicit replacement by the administrator, not a plaintext fallback.
func Open(value, masterKey string) (string, error) {
	if len(value) > MaxStoredSize {
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

// Seal always treats input as new plaintext and preserves the historical format.
func Seal(value, masterKey string) (string, error) {
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

func Migrate(value, masterKey string) (string, bool, error) {
	if _, err := Open(value, masterKey); err != nil {
		return "", false, err
	}
	data, err := hex.DecodeString(value)
	if value == "" || (err == nil && len(data) >= 28) {
		return value, false, nil
	}
	sealed, err := Seal(value, masterKey)
	return sealed, err == nil, err
}
