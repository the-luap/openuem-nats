// Package servicecredentials reads protected database and encryption inputs for
// private OpenUEM services. It never returns input values through error messages.
package servicecredentials

import (
	"bytes"
	"errors"
	"io"
	"net/url"

	"github.com/open-uem/nats/enrollment/keyfile"
)

var ErrConfiguration = errors.New("service credentials require valid, unambiguous protected configuration")

// DatabaseURL permits exactly one source. Existing raw driver grammar remains
// compatible; file inputs must be bounded network PostgreSQL URLs. Selecting a
// missing or invalid file never falls back to an environment value.
func DatabaseURL(raw, path string) (string, error) {
	if path == "" {
		if raw == "" {
			return "", ErrConfiguration
		}
		return raw, nil
	}
	if raw != "" {
		return "", ErrConfiguration
	}
	value, err := readASCII(path, 1, 8192)
	if err != nil {
		return "", err
	}
	defer clear(value)
	parsed, err := url.Parse(string(value))
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Opaque != "" || parsed.Hostname() == "" || parsed.Fragment != "" || len(parsed.Path) < 2 {
		return "", ErrConfiguration
	}
	if _, err = url.ParseQuery(parsed.RawQuery); err != nil {
		return "", ErrConfiguration
	}
	return string(value), nil
}

// EncryptionKey returns the actual 32-byte AES input without decoding it. An
// absent key remains optional for services that do not process encrypted tasks;
// any selected source must be valid and cannot compete with another source.
func EncryptionKey(raw, path string) (string, error) {
	if path == "" {
		if raw != "" && len(raw) != 32 {
			return "", ErrConfiguration
		}
		return raw, nil
	}
	if raw != "" {
		return "", ErrConfiguration
	}
	value, err := readASCII(path, 32, 32)
	if err != nil {
		return "", err
	}
	defer clear(value)
	return string(value), nil
}

func readASCII(path string, minimum, maximum int) ([]byte, error) {
	file, err := keyfile.Open(path, int64(maximum+2))
	if err != nil {
		return nil, ErrConfiguration
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum+3)))
	if err != nil {
		clear(data)
		return nil, ErrConfiguration
	}
	value := bytes.TrimSuffix(data, []byte("\n"))
	if len(value) != len(data) {
		value = bytes.TrimSuffix(value, []byte("\r"))
	}
	if len(value) < minimum || len(value) > maximum || bytes.ContainsFunc(value, func(r rune) bool { return r < 33 || r > 126 }) {
		clear(data)
		return nil, ErrConfiguration
	}
	return value, nil
}
