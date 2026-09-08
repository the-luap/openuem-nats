// Package artifacts authenticates immutable desktop installer releases. Release
// signatures are separate from the operating system's native code signatures.
package artifacts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"time"

	"github.com/open-uem/nats/enrollment/internal/strictjson"
)

const (
	Schema          = 1
	MaxEnvelopeSize = 32 << 10
	MaxPackageSize  = 512 << 20
	domain          = "openuem/desktop-installer-manifest/v1\x00"
)

var (
	ErrInvalid     = errors.New("invalid installer release")
	ErrUntrusted   = errors.New("installer release signature is not trusted")
	ErrExpired     = errors.New("installer release is not currently valid")
	ErrRollback    = errors.New("installer release is older than the accepted sequence")
	ErrTarget      = errors.New("installer release does not support this target")
	ErrPackage     = errors.New("installer content does not match the approved release")
	versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-(alpha|beta|rc)\.(0|[1-9][0-9]{0,8}))?$`)
)

// Manifest approves one immutable installer for each supported platform/CPU
// pair. Sequence is monotonic across releases, including emergency rollback
// releases: republishing an older binary needs a newly authorized sequence.
type Manifest struct {
	Schema      int        `json:"schema"`
	Sequence    uint64     `json:"sequence"`
	Version     string     `json:"version"`
	PublishedAt time.Time  `json:"published_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	Artifacts   []Artifact `json:"artifacts"`
}

type Artifact struct {
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Format       string `json:"format"`
	Filename     string `json:"filename"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
}

type envelope struct {
	Schema    int    `json:"schema"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Verified keeps the authenticated manifest private so a caller cannot mutate
// its approved target or digest between signature and package verification.
type Verified struct {
	manifest Manifest
	digest   string
	keyID    string
}

// Checkpoint must be persisted atomically with acceptance. The digest prevents a
// different release from reusing an already accepted sequence number.
type Checkpoint struct {
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
}

func (v *Verified) Checkpoint() Checkpoint {
	return Checkpoint{Sequence: v.manifest.Sequence, Digest: v.digest}
}

func KeyID(key ed25519.PublicKey) string {
	if len(key) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

func (v *Verified) Manifest() Manifest {
	copy := v.manifest
	copy.Artifacts = append([]Artifact(nil), copy.Artifacts...)
	return copy
}

func (v *Verified) Digest() string       { return v.digest }
func (v *Verified) SigningKeyID() string { return v.keyID }

// Select never guesses a CPU architecture or silently substitutes another target.
func (v *Verified) Select(platform, architecture string) (Artifact, error) {
	for _, item := range v.manifest.Artifacts {
		if item.Platform == platform && item.Architecture == architecture {
			return item, nil
		}
	}
	return Artifact{}, ErrTarget
}

func (v *Verified) ValidAt(now time.Time, checkpoint Checkpoint) error {
	if err := validate(v.manifest, now, checkpoint.Sequence); err != nil {
		return err
	}
	return v.checkpoint(checkpoint)
}

func (v *Verified) checkpoint(previous Checkpoint) error {
	if previous.Sequence == 0 && previous.Digest == "" {
		return nil
	}
	digest, err := hex.DecodeString(previous.Digest)
	if previous.Sequence == 0 || previous.Sequence > math.MaxInt64 || err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != previous.Digest {
		return ErrInvalid
	}
	if v.manifest.Sequence < previous.Sequence || (v.manifest.Sequence == previous.Sequence && v.digest != previous.Digest) {
		return ErrRollback
	}
	return nil
}

// VerifyPackage bounds reads to the signed size plus one byte. The caller must
// verify the actual file that will be served or installed and avoid reopening a
// replaceable path after this check. Native OS signature checks remain mandatory.
func (v *Verified) VerifyPackage(platform, architecture string, r io.Reader) error {
	item, err := v.Select(platform, architecture)
	if err != nil {
		return err
	}
	if r == nil {
		return ErrPackage
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(r, item.Size+1))
	if err != nil || n != item.Size {
		return ErrPackage
	}
	want, _ := hex.DecodeString(item.SHA256)
	if subtle.ConstantTimeCompare(hash.Sum(nil), want) != 1 {
		return ErrPackage
	}
	return nil
}

// Sign is intended for the release pipeline, after native signing/notarization
// and their platform verification. The signing key is never part of a manifest.
func Sign(manifest Manifest, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	valid := subtle.ConstantTimeCompare(derived, key) == 1
	clear(derived)
	if !valid {
		return nil, ErrInvalid
	}
	if err := validate(manifest, now, 0); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		return nil, ErrInvalid
	}
	result, err := json.Marshal(envelope{
		Schema: Schema, KeyID: KeyID(key.Public().(ed25519.PublicKey)),
		Payload:   base64.RawStdEncoding.EncodeToString(payload),
		Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, signedBytes(payload))),
	})
	if err != nil || len(result) > MaxEnvelopeSize {
		return nil, ErrInvalid
	}
	return result, nil
}

// Verify requires an explicit pinned release-key ring. HTTPS host certificates,
// organization CAs and keys supplied in the envelope are not trust roots here.
// Persist the accepted checkpoint with the installation/console state to reject
// rollback after a restart; an in-memory comparison alone is insufficient.
func Verify(data []byte, trusted []ed25519.PublicKey, now time.Time, checkpoint Checkpoint) (*Verified, error) {
	if len(data) == 0 || len(data) > MaxEnvelopeSize || len(trusted) == 0 || len(trusted) > 8 {
		return nil, ErrInvalid
	}
	var wrapped envelope
	if err := strictJSON(data, &wrapped); err != nil || wrapped.Schema != Schema {
		return nil, ErrInvalid
	}
	var public ed25519.PublicKey
	for _, key := range trusted {
		if len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalid
		}
		if KeyID(key) == wrapped.KeyID {
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
	signature, err := base64.RawStdEncoding.Strict().DecodeString(wrapped.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawStdEncoding.EncodeToString(signature) != wrapped.Signature {
		return nil, ErrInvalid
	}
	if !ed25519.Verify(public, signedBytes(payload), signature) {
		return nil, ErrUntrusted
	}
	var manifest Manifest
	if err := strictJSON(payload, &manifest); err != nil {
		return nil, ErrInvalid
	}
	if err := validate(manifest, now, checkpoint.Sequence); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	verified := &Verified{manifest: manifest, digest: hex.EncodeToString(digest[:]), keyID: wrapped.KeyID}
	if err := verified.checkpoint(checkpoint); err != nil {
		return nil, err
	}
	return verified, nil
}

func signedBytes(payload []byte) []byte {
	data := make([]byte, len(domain)+len(payload))
	copy(data, domain)
	copy(data[len(domain):], payload)
	return data
}

func validate(m Manifest, now time.Time, minimumSequence uint64) error {
	if m.Schema != Schema || m.Sequence == 0 || m.Sequence > math.MaxInt64 || !versionPattern.MatchString(m.Version) || len(m.Artifacts) == 0 || len(m.Artifacts) > 4 || m.PublishedAt.IsZero() || m.ExpiresAt.IsZero() {
		return ErrInvalid
	}
	if m.Sequence < minimumSequence {
		return ErrRollback
	}
	if m.PublishedAt.After(now.Add(5*time.Minute)) || !m.ExpiresAt.After(now) || !m.ExpiresAt.After(m.PublishedAt) || m.ExpiresAt.Sub(m.PublishedAt) > 30*24*time.Hour {
		return ErrExpired
	}
	targets := make(map[string]bool)
	for _, item := range m.Artifacts {
		if (item.Platform != "windows" && item.Platform != "macos") || (item.Architecture != "amd64" && item.Architecture != "arm64") || item.Size <= 0 || item.Size > MaxPackageSize {
			return ErrInvalid
		}
		if (item.Platform == "windows" && item.Format != "exe" && item.Format != "msi") || (item.Platform == "macos" && item.Format != "pkg") {
			return ErrInvalid
		}
		want := "openuem-agent-" + m.Version + "-" + item.Platform + "-" + item.Architecture + "." + item.Format
		if item.Filename != want {
			return ErrInvalid
		}
		digest, err := hex.DecodeString(item.SHA256)
		if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != item.SHA256 {
			return ErrInvalid
		}
		target := item.Platform + "/" + item.Architecture
		if targets[target] {
			return ErrInvalid
		}
		targets[target] = true
	}
	return nil
}

func strictJSON(data []byte, target any) error {
	if err := strictjson.Unmarshal(data, target); err != nil {
		return ErrInvalid
	}
	return nil
}
