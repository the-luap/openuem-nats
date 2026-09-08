// Package bootstrap authenticates a limited desktop installation configuration.
// Configuration signing and release signing are distinct trust boundaries.
package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/internal/strictjson"
)

const (
	Schema          = 1
	MaxEnvelopeSize = 96 << 10
	domain          = "openuem/desktop-bootstrap-configuration/v1\x00"
)

var (
	ErrInvalid   = errors.New("invalid installation configuration")
	ErrUntrusted = errors.New("installation configuration signature is not trusted")
	ErrExpired   = errors.New("installation configuration is not currently valid")
	ErrTarget    = errors.New("installation configuration does not match this endpoint")
)

// Config binds a limited invitation and its organization/site to an exact
// immutable release and target. The invitation is a short-lived credential;
// neither this document nor its envelope contains endpoint or signing secrets.
type Config struct {
	Schema          int             `json:"schema"`
	Origin          string          `json:"origin"`
	Organization    string          `json:"organization"`
	Site            string          `json:"site"`
	TenantID        int             `json:"tenant_id"`
	SiteID          int             `json:"site_id"`
	Invitation      string          `json:"invitation"`
	Platform        string          `json:"platform"`
	Architecture    string          `json:"architecture"`
	IssuedAt        time.Time       `json:"issued_at"`
	ExpiresAt       time.Time       `json:"expires_at"`
	ReleaseDigest   string          `json:"release_digest"`
	ReleaseEnvelope json.RawMessage `json:"release_envelope"`
}

func (Config) String() string     { return "[limited installation configuration]" }
func (c Config) GoString() string { return c.String() }

// Trust must be supplied independently of the configuration being verified.
// Origin requires prior operator/user authorization. BootstrapKeys are bound to
// that authorized origin through an independent trusted channel, such as verified
// HTTPS to that exact origin, or installer-provisioned pins. ReleaseKeys belong to
// the separate release pipeline. No key from Config/envelope is ever trusted.
type Trust struct {
	Origin        string
	BootstrapKeys []ed25519.PublicKey
	ReleaseKeys   []ed25519.PublicKey
	Checkpoint    artifacts.Checkpoint
	Platform      string
	Architecture  string
}

type envelope struct {
	Schema    int    `json:"schema"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Verified retains its authenticated values privately. Copies returned to the
// caller cannot alter subsequent target/package/checkpoint decisions.
type Verified struct {
	config  Config
	release *artifacts.Verified
	keyID   string
}

func (Verified) String() string               { return "[verified installation configuration]" }
func (v Verified) GoString() string           { return v.String() }
func (Verified) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

func (v *Verified) Config() Config {
	c := v.config
	c.ReleaseEnvelope = bytes.Clone(c.ReleaseEnvelope)
	return c
}

func (v *Verified) Checkpoint() artifacts.Checkpoint { return v.release.Checkpoint() }
func (v *Verified) SigningKeyID() string             { return v.keyID }
func (v *Verified) Artifact() artifacts.Artifact {
	artifact, _ := v.release.Select(v.config.Platform, v.config.Architecture)
	return artifact
}
func (v *Verified) ReleaseVersion() string { return v.release.Manifest().Version }
func (v *Verified) VerifyPackage(reader io.Reader) error {
	return v.release.VerifyPackage(v.config.Platform, v.config.Architecture, reader)
}
func (v *Verified) DownloadURL() string {
	return v.config.Origin + "/enroll/desktop/releases/" + v.config.ReleaseDigest + "/" + v.config.Platform + "/" + v.config.Architecture
}

func (v *Verified) ValidAt(now time.Time, checkpoint artifacts.Checkpoint) error {
	if err := validate(v.config, now); err != nil {
		return err
	}
	return v.release.ValidAt(now, checkpoint)
}

// Sign is used by the enrollment service with a dedicated configuration key,
// never a CA or release private key. Callers select metadata from the current
// approved catalog and enforce invitation lifetime/revocation independently.
// Verification still requires the separately pinned release signature.
func Sign(config Config, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	valid := subtle.ConstantTimeCompare(derived, key) == 1
	clear(derived)
	if !valid {
		return nil, ErrInvalid
	}
	if err := validate(config, now); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(config)
	if err != nil || len(payload) > MaxEnvelopeSize/2 {
		return nil, ErrInvalid
	}
	defer clear(payload)
	message := signedBytes(payload)
	defer clear(message)
	data, err := json.Marshal(envelope{Schema: Schema, KeyID: artifacts.KeyID(key.Public().(ed25519.PublicKey)), Payload: base64.RawStdEncoding.EncodeToString(payload), Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))})
	if err != nil || len(data) > MaxEnvelopeSize {
		return nil, ErrInvalid
	}
	return data, nil
}

func Verify(data []byte, trust Trust, now time.Time) (*Verified, error) {
	if len(data) == 0 || len(data) > MaxEnvelopeSize || !validTrust(trust) {
		return nil, ErrInvalid
	}
	var wrapped envelope
	if err := strictjson.Unmarshal(data, &wrapped); err != nil || wrapped.Schema != Schema {
		return nil, ErrInvalid
	}
	var public ed25519.PublicKey
	for _, key := range trust.BootstrapKeys {
		if artifacts.KeyID(key) == wrapped.KeyID {
			public = key
		}
	}
	if public == nil {
		return nil, ErrUntrusted
	}
	payload, err := base64.RawStdEncoding.Strict().DecodeString(wrapped.Payload)
	if err != nil || len(payload) == 0 || len(payload) > MaxEnvelopeSize/2 || base64.RawStdEncoding.EncodeToString(payload) != wrapped.Payload {
		return nil, ErrInvalid
	}
	defer clear(payload)
	signature, err := base64.RawStdEncoding.Strict().DecodeString(wrapped.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawStdEncoding.EncodeToString(signature) != wrapped.Signature {
		return nil, ErrInvalid
	}
	message := signedBytes(payload)
	defer clear(message)
	if !ed25519.Verify(public, message, signature) {
		return nil, ErrUntrusted
	}
	var config Config
	if err := strictjson.Unmarshal(payload, &config); err != nil {
		return nil, ErrInvalid
	}
	if err := validate(config, now); err != nil {
		return nil, err
	}
	if config.Origin != trust.Origin || config.Platform != trust.Platform || config.Architecture != trust.Architecture {
		return nil, ErrTarget
	}
	release, err := artifacts.Verify(config.ReleaseEnvelope, trust.ReleaseKeys, now, trust.Checkpoint)
	if err != nil {
		return nil, err
	}
	if release.Digest() != config.ReleaseDigest || config.ExpiresAt.After(release.Manifest().ExpiresAt) {
		return nil, ErrInvalid
	}
	if _, err := release.Select(config.Platform, config.Architecture); err != nil {
		return nil, ErrTarget
	}
	return &Verified{config: config, release: release, keyID: wrapped.KeyID}, nil
}

func validate(c Config, now time.Time) error {
	digest, err := hex.DecodeString(c.ReleaseDigest)
	if c.Schema != Schema || !enrollment.ValidOrigin(c.Origin) || !validLabel(c.Organization) || !validLabel(c.Site) || c.TenantID <= 0 || c.SiteID <= 0 || !enrollment.ValidToken(c.Invitation) || !validTarget(c.Platform, c.Architecture) || err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != c.ReleaseDigest || len(c.ReleaseEnvelope) == 0 || len(c.ReleaseEnvelope) > artifacts.MaxEnvelopeSize || !json.Valid(c.ReleaseEnvelope) || c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() {
		return ErrInvalid
	}
	if c.IssuedAt.After(now.Add(5*time.Minute)) || !c.ExpiresAt.After(now) || !c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > 7*24*time.Hour {
		return ErrExpired
	}
	return nil
}

func validLabel(value string) bool {
	if value == "" || len(value) > 255 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func validTarget(platform, architecture string) bool {
	return (platform == "windows" || platform == "macos") && (architecture == "amd64" || architecture == "arm64")
}

func validTrust(t Trust) bool {
	if !enrollment.ValidOrigin(t.Origin) || !validTarget(t.Platform, t.Architecture) || len(t.BootstrapKeys) == 0 || len(t.BootstrapKeys) > 8 || len(t.ReleaseKeys) == 0 || len(t.ReleaseKeys) > 8 {
		return false
	}
	seen := make(map[string]bool)
	for _, ring := range [][]ed25519.PublicKey{t.BootstrapKeys, t.ReleaseKeys} {
		for _, key := range ring {
			id := artifacts.KeyID(key)
			if id == "" || seen[id] {
				return false
			}
			seen[id] = true
		}
	}
	return true
}

func signedBytes(payload []byte) []byte {
	data := make([]byte, len(domain)+len(payload))
	copy(data, domain)
	copy(data[len(domain):], payload)
	return data
}
