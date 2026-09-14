// Package netbirdinstall describes exact, organization-approved Unix NetBird
// packages. A descriptor is not execution authority: its approval and current
// recipient must be authenticated by the caller before download or installation.
package netbirdinstall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	Schema         = 1
	MaxMessage     = 8 << 10
	MaxPackageSize = 512 << 20
)

var ErrInvalid = errors.New("invalid approved NetBird package")

type Package struct {
	Schema       int    `json:"schema"`
	ApprovalID   string `json:"approval_id"`
	TenantID     int64  `json:"tenant_id"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Format       string `json:"format"`
	PackageID    string `json:"package_id"`
	Version      string `json:"version"`
	URL          string `json:"url"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
}
type wirePackage Package

// URLs may contain private source coordinates. Only Encode deliberately exposes
// them; normal formatting and incidental JSON serialization cannot disclose them.
func (Package) String() string               { return "NetBird package (source redacted)" }
func (p Package) GoString() string           { return p.String() }
func (Package) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

func (p Package) Valid() bool {
	id, err := uuid.Parse(p.ApprovalID)
	if p.Schema != Schema || err != nil || id == uuid.Nil || id.String() != p.ApprovalID || p.TenantID <= 0 || p.Size <= 0 || p.Size > MaxPackageSize || !validVersion(p.Version) {
		return false
	}
	hash, err := hex.DecodeString(p.SHA256)
	if err != nil || len(hash) != sha256.Size || hex.EncodeToString(hash) != p.SHA256 {
		return false
	}
	switch p.Platform {
	case "linux":
		if (p.Format != "deb" && p.Format != "rpm") || p.PackageID != "netbird" || (p.Architecture != "amd64" && p.Architecture != "arm64" && p.Architecture != "386") {
			return false
		}
	case "macos":
		if p.Format != "pkg" || p.PackageID != "io.netbird.client" || (p.Architecture != "amd64" && p.Architecture != "arm64") {
			return false
		}
	default:
		return false
	}
	return validURL(p.URL, p.Format)
}

func validVersion(v string) bool {
	if len(v) == 0 || len(v) > 128 || !((v[0] >= '0' && v[0] <= '9') || (v[0] >= 'a' && v[0] <= 'z') || (v[0] >= 'A' && v[0] <= 'Z')) {
		return false
	}
	for _, r := range v {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || strings.ContainsRune(".+:~_-", r)) {
			return false
		}
	}
	return true
}

func validURL(value, format string) bool {
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsFunc(value, unicode.IsControl) || strings.Contains(value, "#") {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.ForceQuery || strings.Contains(u.Host, "\\") || !strings.HasSuffix(u.Path, "."+format) {
		return false
	}
	if u.Port() != "" {
		n, err := strconv.Atoi(u.Port())
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != u.Port() {
			return false
		}
	}
	return true
}

func (p Package) MatchesTarget(tenant int64, platform, architecture string) bool {
	return p.Valid() && p.TenantID == tenant && p.Platform == platform && p.Architecture == architecture
}

func Encode(p Package) ([]byte, error) {
	if !p.Valid() {
		return nil, ErrInvalid
	}
	data, err := json.Marshal(wirePackage(p))
	if err != nil || len(data) > MaxMessage {
		return nil, ErrInvalid
	}
	return data, nil
}
func (p Package) Digest() (string, error) {
	data, err := Encode(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Decode rejects aliases, duplicates, null values and unsupported fields before
// assigning a type. The complete descriptor, including approval/scope and source,
// must remain bound to its authenticated immutable task and review fingerprint.
func Decode(data []byte) (Package, error) {
	if len(data) == 0 || len(data) > MaxMessage || !utf8.Valid(data) {
		return Package{}, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return Package{}, ErrInvalid
	}
	fields := map[string]bool{"schema": true, "approval_id": true, "tenant_id": true, "platform": true, "architecture": true, "format": true, "package_id": true, "version": true, "url": true, "size": true, "sha256": true}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return Package{}, ErrInvalid
		}
		key, ok := token.(string)
		if !ok || !fields[key] || seen[key] {
			return Package{}, ErrInvalid
		}
		seen[key] = true
		value, err := d.Token()
		if err != nil || value == nil {
			return Package{}, ErrInvalid
		}
		switch key {
		case "schema", "tenant_id", "size":
			if _, ok := value.(json.Number); !ok {
				return Package{}, ErrInvalid
			}
		default:
			if _, ok := value.(string); !ok {
				return Package{}, ErrInvalid
			}
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || len(seen) != len(fields) {
		return Package{}, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return Package{}, ErrInvalid
	}
	var p wirePackage
	if json.Unmarshal(data, &p) != nil || !Package(p).Valid() {
		return Package{}, ErrInvalid
	}
	return Package(p), nil
}
