package artifacts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (Manifest, ed25519.PublicKey, ed25519.PrivateKey, []byte, time.Time) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(private) })
	// These bytes exercise release integrity, not an executable/native signature.
	content := []byte("test installer bytes")
	digest := sha256.Sum256(content)
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	m := Manifest{Schema: Schema, Sequence: 42, Version: "0.12.0-beta.1", PublishedAt: now.Add(-time.Hour), ExpiresAt: now.Add(7 * 24 * time.Hour), Artifacts: []Artifact{{Platform: "windows", Architecture: "amd64", Format: "msi", Filename: "openuem-agent-0.12.0-beta.1-windows-amd64.msi", Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])}}}
	return m, public, private, content, now
}

func signedRaw(t *testing.T, payload []byte, key ed25519.PrivateKey) []byte {
	t.Helper()
	data, err := json.Marshal(envelope{Schema: Schema, KeyID: KeyID(key.Public().(ed25519.PublicKey)), Payload: base64.RawStdEncoding.EncodeToString(payload), Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, signedBytes(payload)))})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestReleasePinsTargetContentValidityAndPersistentCheckpoint(t *testing.T) {
	m, pub, key, content, now := fixture(t)
	data, err := Sign(m, key, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(data, []ed25519.PublicKey{pub}, now, Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	if err = verified.VerifyPackage("windows", "amd64", bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if _, err = verified.Select("windows", "arm64"); !errors.Is(err, ErrTarget) {
		t.Fatal("silently selected an incompatible installer", err)
	}
	if err = verified.VerifyPackage("macos", "amd64", bytes.NewReader(content)); !errors.Is(err, ErrTarget) {
		t.Fatal("accepted a Windows installer on Mac", err)
	}
	copy := verified.Manifest()
	copy.Artifacts[0].SHA256 = strings.Repeat("0", 64)
	copy.Sequence = 1
	if verified.Manifest().Sequence != 42 || verified.Manifest().Artifacts[0].SHA256 != m.Artifacts[0].SHA256 {
		t.Fatal("caller mutated authenticated metadata")
	}
	checkpoint := verified.Checkpoint()
	if _, err = Verify(data, []ed25519.PublicKey{pub}, now, checkpoint); err != nil {
		t.Fatal("identical restart acceptance was rejected", err)
	}
	if err = verified.ValidAt(m.ExpiresAt, checkpoint); !errors.Is(err, ErrExpired) {
		t.Fatal("accepted an expired cached release", err)
	}
	for _, previous := range []Checkpoint{{Sequence: 43, Digest: checkpoint.Digest}, {Sequence: 42, Digest: strings.Repeat("0", 64)}} {
		if _, err = Verify(data, []ed25519.PublicKey{pub}, now, previous); !errors.Is(err, ErrRollback) {
			t.Fatal("accepted rollback or sequence reuse", err)
		}
	}
	if _, err = Verify(data, []ed25519.PublicKey{pub}, now, Checkpoint{Sequence: 42}); !errors.Is(err, ErrInvalid) {
		t.Fatal("ignored a corrupt persisted checkpoint", err)
	}
	m.Sequence++
	newData, err := Sign(m, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(newData, []ed25519.PublicKey{pub}, now, checkpoint); err != nil {
		t.Fatal("rejected a newly approved sequence", err)
	}
}

func TestReleaseRejectsWrongKeyTamperingAmbiguousJSONAndUnknownFields(t *testing.T) {
	m, pub, key, _, now := fixture(t)
	data, err := Sign(m, key, now)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(data, []ed25519.PublicKey{other}, now, Checkpoint{}); !errors.Is(err, ErrUntrusted) {
		t.Fatal("trusted an envelope-supplied key identifier", err)
	}
	var wrap envelope
	if err = json.Unmarshal(data, &wrap); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.RawStdEncoding.DecodeString(wrap.Payload)
	wrap.Payload = base64.RawStdEncoding.EncodeToString(bytes.Replace(payload, []byte(`"sequence":42`), []byte(`"sequence":41`), 1))
	modified, _ := json.Marshal(wrap)
	if _, err = Verify(modified, []ed25519.PublicKey{pub}, now, Checkpoint{}); !errors.Is(err, ErrUntrusted) {
		t.Fatal("accepted modified release metadata", err)
	}
	for _, invalid := range [][]byte{
		append([]byte(`{"schema":1,`), data[1:]...),
		append([]byte(`{"Schema":1,`), data[1:]...),
		append([]byte(`{"\u017fchema":1,`), data[1:]...),
		append(append([]byte(nil), data...), []byte(` {}`)...),
		append([]byte(`{"unexpected":true,`), data[1:]...),
		signedRaw(t, append([]byte(`{"schema":1,`), payload[1:]...), key),
		signedRaw(t, append([]byte(`{"Schema":1,`), payload[1:]...), key),
		signedRaw(t, append([]byte(`{"\u017fchema":1,`), payload[1:]...), key),
		signedRaw(t, append([]byte(`{"unexpected":true,`), payload[1:]...), key),
		signedRaw(t, bytes.Replace(payload, []byte(`"platform":"windows"`), []byte(`"platform":"windows","platform":"windows"`), 1), key),
		signedRaw(t, append(append([]byte(nil), payload...), []byte(` null`)...), key),
	} {
		if _, err = Verify(invalid, []ed25519.PublicKey{pub}, now, Checkpoint{}); !errors.Is(err, ErrInvalid) {
			t.Fatal("accepted ambiguous or extensible release JSON", err)
		}
	}
	wrap.Payload = base64.RawStdEncoding.EncodeToString(payload)
	wrap.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, payload))
	modified, _ = json.Marshal(wrap)
	if _, err = Verify(modified, []ed25519.PublicKey{pub}, now, Checkpoint{}); !errors.Is(err, ErrUntrusted) {
		t.Fatal("accepted a signature from another protocol domain", err)
	}
	if _, err = Verify(bytes.Repeat([]byte("x"), MaxEnvelopeSize+1), []ed25519.PublicKey{pub}, now, Checkpoint{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("accepted an oversized release", err)
	}
}

func TestEverySupportedInstallerTargetAndReleaseKeyRotation(t *testing.T) {
	manifest, public, private, content, now := fixture(t)
	item := manifest.Artifacts[0]
	manifest.Artifacts = nil
	for _, platform := range []string{"windows", "macos"} {
		for _, architecture := range []string{"amd64", "arm64"} {
			artifact := item
			artifact.Platform, artifact.Architecture = platform, architecture
			if platform == "macos" {
				artifact.Format = "pkg"
			}
			artifact.Filename = "openuem-agent-" + manifest.Version + "-" + platform + "-" + architecture + "." + artifact.Format
			manifest.Artifacts = append(manifest.Artifacts, artifact)
		}
	}
	data, err := Sign(manifest, private, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(data, []ed25519.PublicKey{public}, now, Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range manifest.Artifacts {
		if err = verified.VerifyPackage(artifact.Platform, artifact.Architecture, bytes.NewReader(content)); err != nil {
			t.Fatal(err)
		}
	}
	nextPublic, nextPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(nextPrivate)
	rotated, err := Sign(manifest, nextPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(rotated, []ed25519.PublicKey{public}, now, verified.Checkpoint()); !errors.Is(err, ErrUntrusted) {
		t.Fatal("accepted an unconfigured rotation key", err)
	}
	next, err := Verify(rotated, []ed25519.PublicKey{public, nextPublic}, now, verified.Checkpoint())
	if err != nil || next.Digest() != verified.Digest() || next.SigningKeyID() != KeyID(nextPublic) {
		t.Fatal("rotation changed immutable manifest identity", err)
	}
	if _, err = Verify(data, []ed25519.PublicKey{nextPublic}, now, verified.Checkpoint()); !errors.Is(err, ErrUntrusted) {
		t.Fatal("retired key remained trusted", err)
	}
}

func TestSignedReleaseStillValidatesTargetNamesVersionsAndBounds(t *testing.T) {
	base, pub, key, _, now := fixture(t)
	mutations := map[string]func(*Manifest){
		"path traversal":            func(m *Manifest) { m.Artifacts[0].Filename = "../" + m.Artifacts[0].Filename },
		"URL instead of name":       func(m *Manifest) { m.Artifacts[0].Filename = "https://attacker.test/installer.msi" },
		"encoded separator":         func(m *Manifest) { m.Artifacts[0].Filename = "%2f" + m.Artifacts[0].Filename },
		"other architecture":        func(m *Manifest) { m.Artifacts[0].Architecture = "x64" },
		"platform format mismatch":  func(m *Manifest) { m.Artifacts[0].Format = "pkg" },
		"negative size":             func(m *Manifest) { m.Artifacts[0].Size = -1 },
		"huge size":                 func(m *Manifest) { m.Artifacts[0].Size = MaxPackageSize + 1 },
		"noncanonical digest":       func(m *Manifest) { m.Artifacts[0].SHA256 = strings.ToUpper(m.Artifacts[0].SHA256) },
		"duplicate target":          func(m *Manifest) { m.Artifacts = append(m.Artifacts, m.Artifacts[0]) },
		"short version":             func(m *Manifest) { m.Version = "0.12" },
		"leading zero":              func(m *Manifest) { m.Version = "0.012.0" },
		"filename version mismatch": func(m *Manifest) { m.Version = "0.13.0" },
		"zero sequence":             func(m *Manifest) { m.Sequence = 0 },
		"unsupported schema":        func(m *Manifest) { m.Schema = 2 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			m := base
			m.Artifacts = append([]Artifact(nil), base.Artifacts...)
			mutate(&m)
			payload, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = Verify(signedRaw(t, payload, key), []ed25519.PublicKey{pub}, now, Checkpoint{}); !errors.Is(err, ErrInvalid) {
				t.Fatal("trusted malformed signed metadata", err)
			}
			if _, err = Sign(m, key, now); !errors.Is(err, ErrInvalid) {
				t.Fatal("release signer emitted malformed metadata", err)
			}
		})
	}
	for _, mutate := range []func(*Manifest){func(m *Manifest) { m.ExpiresAt = now }, func(m *Manifest) { m.PublishedAt = now.Add(6 * time.Minute) }, func(m *Manifest) { m.ExpiresAt = m.PublishedAt.Add(31 * 24 * time.Hour) }} {
		m := base
		mutate(&m)
		payload, _ := json.Marshal(m)
		if _, err := Verify(signedRaw(t, payload, key), []ed25519.PublicKey{pub}, now, Checkpoint{}); !errors.Is(err, ErrExpired) {
			t.Fatal("accepted invalid release validity", err)
		}
	}
}

type endlessReader struct{ count int }

func (r *endlessReader) Read(p []byte) (int, error) { clear(p); r.count += len(p); return len(p), nil }

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestPackageVerificationRejectsTruncationModificationAndUnboundedInput(t *testing.T) {
	m, pub, key, content, now := fixture(t)
	data, err := Sign(m, key, now)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(data, []ed25519.PublicKey{pub}, now, Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	infinite := &endlessReader{}
	for _, reader := range []io.Reader{nil, bytes.NewReader(content[:len(content)-1]), bytes.NewReader(append(append([]byte(nil), content...), 'x')), strings.NewReader(strings.Repeat("x", len(content))), infinite, failedReader{}} {
		if err = v.VerifyPackage("windows", "amd64", reader); !errors.Is(err, ErrPackage) {
			t.Fatal("accepted mismatched package bytes", err)
		}
	}
	if infinite.count != len(content)+1 {
		t.Fatal("read more than the bounded signed package size", infinite.count)
	}
}
