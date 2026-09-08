package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment/artifacts"
)

type fixture struct {
	config                   Config
	trust                    Trust
	bootstrapKey, releaseKey ed25519.PrivateKey
	now                      time.Time
	content                  []byte
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	bootstrapPublic, bootstrapKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	releasePublic, releaseKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(bootstrapKey); clear(releaseKey) })
	content := []byte("non-executable isolated installer fixture")
	digest := sha256.Sum256(content)
	now := time.Date(2026, 9, 8, 4, 0, 0, 0, time.UTC)
	manifest := artifacts.Manifest{Schema: 1, Sequence: 42, Version: "0.12.0", PublishedAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour), Artifacts: []artifacts.Artifact{{Platform: "windows", Architecture: "amd64", Format: "msi", Filename: "openuem-agent-0.12.0-windows-amd64.msi", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(content))}}}
	releaseEnvelope, err := artifacts.Sign(manifest, releaseKey, now)
	if err != nil {
		t.Fatal(err)
	}
	release, err := artifacts.Verify(releaseEnvelope, []ed25519.PublicKey{releasePublic}, now, artifacts.Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Schema: Schema, Origin: "https://uem.example.test", Organization: "Example organization", Site: "Berlin", TenantID: 3, SiteID: 4, Invitation: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{13}, 32)), Platform: "windows", Architecture: "amd64", IssuedAt: now, ExpiresAt: now.Add(time.Hour), ReleaseDigest: release.Digest(), ReleaseEnvelope: releaseEnvelope}
	return fixture{config: config, trust: Trust{Origin: config.Origin, BootstrapKeys: []ed25519.PublicKey{bootstrapPublic}, ReleaseKeys: []ed25519.PublicKey{releasePublic}, Checkpoint: release.Checkpoint(), Platform: config.Platform, Architecture: config.Architecture}, bootstrapKey: bootstrapKey, releaseKey: releaseKey, now: now, content: content}
}

func signedRaw(t *testing.T, payload []byte, key ed25519.PrivateKey, prefix string) []byte {
	t.Helper()
	data, err := json.Marshal(envelope{Schema: Schema, KeyID: artifacts.KeyID(key.Public().(ed25519.PublicKey)), Payload: base64.RawStdEncoding.EncodeToString(payload), Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(prefix), payload...)))})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSignedConfigurationBindsAuthorizedOriginInvitationScopeTargetAndRelease(t *testing.T) {
	f := newFixture(t)
	data, err := Sign(f.config, f.bootstrapKey, f.now)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(data, f.trust, f.now)
	if err != nil {
		t.Fatal(err)
	}
	c := v.Config()
	if c.Origin != f.trust.Origin || c.Invitation != f.config.Invitation || c.TenantID != 3 || c.SiteID != 4 || v.Checkpoint() != f.trust.Checkpoint || v.ReleaseVersion() != "0.12.0" || v.SigningKeyID() != artifacts.KeyID(f.trust.BootstrapKeys[0]) {
		t.Fatal("verified configuration lost authenticated fields")
	}
	if v.DownloadURL() != f.config.Origin+"/enroll/desktop/releases/"+f.config.ReleaseDigest+"/windows/amd64" {
		t.Fatal("download URL left the authorized release/origin")
	}
	if err := v.VerifyPackage(bytes.NewReader(f.content)); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyPackage(bytes.NewReader(append(bytes.Clone(f.content), 0))); !errors.Is(err, artifacts.ErrPackage) {
		t.Fatal("signed configuration accepted changed package bytes", err)
	}
	c.ReleaseEnvelope[0] ^= 1
	c.Invitation = "replacement"
	c.Platform = "macos"
	artifact := v.Artifact()
	artifact.SHA256 = strings.Repeat("0", 64)
	if v.Config().Invitation != f.config.Invitation || v.Artifact().SHA256 == artifact.SHA256 || !bytes.Equal(v.Config().ReleaseEnvelope, f.config.ReleaseEnvelope) {
		t.Fatal("returned copy mutated verified state")
	}
	if err := v.ValidAt(f.now.Add(2*time.Hour), f.trust.Checkpoint); !errors.Is(err, ErrExpired) {
		t.Fatal("verified configuration ignored expiry", err)
	}
	if err := v.ValidAt(f.now, artifacts.Checkpoint{Sequence: 43, Digest: f.config.ReleaseDigest}); !errors.Is(err, artifacts.ErrRollback) {
		t.Fatal("verified configuration ignored a newer checkpoint", err)
	}
	if strings.Contains(fmt.Sprintf("%+v %#v %+v %#v", f.config, f.config, v, v), f.config.Invitation) {
		t.Fatal("formatted configuration leaked its invitation")
	}
	if _, err := json.Marshal(v); err == nil {
		t.Fatal("verified object unexpectedly serialized its credential")
	}
}

func TestBootstrapSignatureCannotAuthorizeItsOwnKeysOrAnotherOrigin(t *testing.T) {
	f := newFixture(t)
	data, err := Sign(f.config, f.bootstrapKey, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"no origin", "other origin", "other platform", "other architecture", "no bootstrap key", "no release key", "same key for both roles", "wrong bootstrap key", "wrong release key"} {
		t.Run(variant, func(t *testing.T) {
			trust := f.trust
			switch variant {
			case "no origin":
				trust.Origin = ""
			case "other origin":
				trust.Origin = "https://other.example.test"
			case "other platform":
				trust.Platform = "macos"
			case "other architecture":
				trust.Architecture = "arm64"
			case "no bootstrap key":
				trust.BootstrapKeys = nil
			case "no release key":
				trust.ReleaseKeys = nil
			case "same key for both roles":
				trust.BootstrapKeys = trust.ReleaseKeys
			case "wrong bootstrap key":
				public, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				trust.BootstrapKeys = []ed25519.PublicKey{public}
			case "wrong release key":
				public, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				trust.ReleaseKeys = []ed25519.PublicKey{public}
			}
			if _, err := Verify(data, trust, f.now); err == nil {
				t.Fatal("configuration supplied or replaced its own trust")
			}
		})
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["public_key"] = json.RawMessage(`"self-asserted"`)
	modified, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(modified, f.trust, f.now); !errors.Is(err, ErrInvalid) {
		t.Fatal("self-supplied signing key field accepted", err)
	}
	payload, err := json.Marshal(f.config)
	if err != nil {
		t.Fatal(err)
	}
	wrongDomain := signedRaw(t, payload, f.bootstrapKey, "openuem/desktop-installer-manifest/v1\x00")
	if _, err := Verify(wrongDomain, f.trust, f.now); !errors.Is(err, ErrUntrusted) {
		t.Fatal("release signature domain accepted for a configuration", err)
	}
}

func TestAuthenticatedButInvalidConfigurationIsRejected(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"schema", func(c *Config) { c.Schema++ }},
		{"origin credentials", func(c *Config) { c.Origin = "https://user:secret@uem.example.test" }},
		{"origin redirect", func(c *Config) { c.Origin = "https://other.example.test" }},
		{"missing tenant", func(c *Config) { c.TenantID = 0 }},
		{"negative site", func(c *Config) { c.SiteID = -1 }},
		{"ambiguous organization", func(c *Config) { c.Organization = "Company\nOther" }},
		{"empty site label", func(c *Config) { c.Site = "" }},
		{"invalid invitation", func(c *Config) { c.Invitation += "=" }},
		{"another target", func(c *Config) { c.Platform = "macos" }},
		{"expired", func(c *Config) { c.ExpiresAt = f.now }},
		{"future", func(c *Config) { c.IssuedAt = f.now.Add(6 * time.Minute) }},
		{"excessive validity", func(c *Config) { c.ExpiresAt = f.now.Add(8 * 24 * time.Hour) }},
		{"outlives release", func(c *Config) { c.ExpiresAt = f.now.Add(25 * time.Hour) }},
		{"different release digest", func(c *Config) { c.ReleaseDigest = strings.Repeat("0", 64) }},
		{"no release signature", func(c *Config) { c.ReleaseEnvelope = json.RawMessage(`null`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := f.config
			tc.change(&c)
			payload, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(signedRaw(t, payload, f.bootstrapKey, domain), f.trust, f.now); err == nil {
				t.Fatal("invalid signed configuration accepted")
			}
		})
	}
	data, err := Sign(f.config, f.bootstrapKey, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, checkpoint := range []artifacts.Checkpoint{{Sequence: 43, Digest: f.config.ReleaseDigest}, {Sequence: 42, Digest: strings.Repeat("0", 64)}} {
		trust := f.trust
		trust.Checkpoint = checkpoint
		if _, err := Verify(data, trust, f.now); !errors.Is(err, artifacts.ErrRollback) {
			t.Fatal("configuration reset release rollback protection", err)
		}
	}
}

func TestBootstrapRejectsAmbiguousDocumentsAndNoncanonicalSignatures(t *testing.T) {
	f := newFixture(t)
	payload, err := json.Marshal(f.config)
	if err != nil {
		t.Fatal(err)
	}
	for _, modified := range [][]byte{
		append([]byte(`{"schema":1,`), payload[1:]...),
		bytes.Replace(payload, []byte(`"schema"`), []byte(`"Schema"`), 1),
		append(bytes.Clone(payload), []byte(` {}`)...),
		bytes.Replace(payload, []byte(`"tenant_id":3`), []byte(`"tenant_id":null`), 1),
		bytes.Replace(payload, []byte(`"organization":"Example organization"`), []byte{'"', 'o', 'r', 'g', 'a', 'n', 'i', 'z', 'a', 't', 'i', 'o', 'n', '"', ':', '"', 0xff, '"'}, 1),
		append([]byte(`{"bootstrap_public_key":"self-asserted",`), payload[1:]...),
	} {
		if _, err := Verify(signedRaw(t, modified, f.bootstrapKey, domain), f.trust, f.now); !errors.Is(err, ErrInvalid) {
			t.Fatal("ambiguous signed payload was accepted", err)
		}
	}
	data, err := Sign(f.config, f.bootstrapKey, f.now)
	if err != nil {
		t.Fatal(err)
	}
	var wrapped envelope
	if err := json.Unmarshal(data, &wrapped); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*envelope){
		func(e *envelope) { e.Schema = 0 },
		func(e *envelope) { e.KeyID = strings.ToUpper(e.KeyID) },
		func(e *envelope) { e.Payload += "=" },
		func(e *envelope) { e.Signature += "=" },
		func(e *envelope) {
			e.Signature = base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		},
	} {
		e := wrapped
		change(&e)
		modified, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(modified, f.trust, f.now); err == nil {
			t.Fatal("invalid envelope was accepted")
		}
	}
	for _, modified := range [][]byte{nil, make([]byte, MaxEnvelopeSize+1), append([]byte(`{"schema":1,`), data[1:]...), append(bytes.Clone(data), []byte(` {}`)...)} {
		if _, err := Verify(modified, f.trust, f.now); !errors.Is(err, ErrInvalid) {
			t.Fatal("unbounded or ambiguous envelope was accepted", err)
		}
	}
	brokenKey := bytes.Clone(f.bootstrapKey)
	defer clear(brokenKey)
	brokenKey[len(brokenKey)-1] ^= 1
	if _, err := Sign(f.config, brokenKey, f.now); !errors.Is(err, ErrInvalid) {
		t.Fatal("inconsistent signing key accepted", err)
	}
}
