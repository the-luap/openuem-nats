package netbirdinstall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// Removal identifies the exact installed package inspected for removal. It has
// no source, arbitrary path, executable, arguments or provider credentials.
// StateDigest is the native observer's complete ownership/state fingerprint,
// not a hash of periodic inventory. The native runner must reconstruct it under
// current journal admission before changing any package or service state.
type Removal struct {
	Schema       int    `json:"schema"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Format       string `json:"format"`
	PackageID    string `json:"package_id"`
	Version      string `json:"version"`
	StateDigest  string `json:"state_digest"`
}

func (r Removal) Valid() bool {
	if r.Schema != Schema || !validVersion(r.Version) {
		return false
	}
	digest, err := hex.DecodeString(r.StateDigest)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != r.StateDigest {
		return false
	}
	switch r.Platform {
	case "macos":
		return r.Format == "pkg" && r.PackageID == "io.netbird.client" && (r.Architecture == "arm64" || r.Architecture == "amd64")
	case "linux":
		return (r.Format == "deb" || r.Format == "rpm") && r.PackageID == "netbird" && (r.Architecture == "arm64" || r.Architecture == "amd64" || r.Architecture == "386")
	default:
		return false
	}
}

func EncodeRemoval(r Removal) ([]byte, error) {
	if !r.Valid() {
		return nil, ErrInvalid
	}
	return json.Marshal(r)
}

func (r Removal) Digest() (string, error) {
	data, err := EncodeRemoval(r)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("openuem/netbird/removal/v1\x00"), data...))
	return hex.EncodeToString(digest[:]), nil
}

func DecodeRemoval(data []byte) (Removal, error) {
	if len(data) == 0 || len(data) > MaxMessage || !utf8.Valid(data) {
		return Removal{}, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return Removal{}, ErrInvalid
	}
	fields := map[string]bool{"schema": true, "platform": true, "architecture": true, "format": true, "package_id": true, "version": true, "state_digest": true}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !fields[key] || seen[key] {
			return Removal{}, ErrInvalid
		}
		seen[key] = true
		value, err := d.Token()
		if err != nil || value == nil {
			return Removal{}, ErrInvalid
		}
		if key == "schema" {
			if _, ok := value.(json.Number); !ok {
				return Removal{}, ErrInvalid
			}
		} else if _, ok := value.(string); !ok {
			return Removal{}, ErrInvalid
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || len(seen) != len(fields) {
		return Removal{}, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return Removal{}, ErrInvalid
	}
	var r Removal
	if json.Unmarshal(data, &r) != nil || !r.Valid() {
		return Removal{}, ErrInvalid
	}
	return r, nil
}
