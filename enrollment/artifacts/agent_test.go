package artifacts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestReleaseSeparatelyBindsInstalledExecutableAndInstallerBytes(t *testing.T) {
	manifest, public, key, packageBytes, now := fixture(t)
	agentBytes := []byte("distinct final signed executable fixture")
	digest := sha256.Sum256(agentBytes)
	manifest.Artifacts[0].AgentSize = int64(len(agentBytes))
	manifest.Artifacts[0].AgentSHA256 = hex.EncodeToString(digest[:])
	data, err := Sign(manifest, key, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(data, []ed25519.PublicKey{public}, now, Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	if err := verified.VerifyPackage("windows", "amd64", bytes.NewReader(packageBytes)); err != nil {
		t.Fatal(err)
	}
	if err := verified.VerifyAgent("windows", "amd64", bytes.NewReader(agentBytes)); err != nil {
		t.Fatal(err)
	}
	for _, wrong := range [][]byte{nil, packageBytes, agentBytes[:len(agentBytes)-1], append(bytes.Clone(agentBytes), 0), bytes.Repeat([]byte("x"), len(agentBytes))} {
		if err := verified.VerifyAgent("windows", "amd64", bytes.NewReader(wrong)); !errors.Is(err, ErrAgentBinding) {
			t.Fatal("wrong executable was accepted", err)
		}
	}
	if err := verified.VerifyAgent("macos", "amd64", bytes.NewReader(agentBytes)); !errors.Is(err, ErrTarget) {
		t.Fatal("executable target changed", err)
	}
	copy := verified.Manifest()
	copy.Artifacts[0].AgentSHA256 = strings.Repeat("0", 64)
	if err := verified.VerifyAgent("windows", "amd64", bytes.NewReader(agentBytes)); err != nil {
		t.Fatal("caller changed executable binding", err)
	}
	if err := verified.VerifyAgent("windows", "amd64", nil); !errors.Is(err, ErrAgentBinding) {
		t.Fatal("nil executable accepted", err)
	}
	// The original package proof is never a substitute for the executable proof.
	if err := verified.VerifyPackage("windows", "amd64", bytes.NewReader(agentBytes)); !errors.Is(err, ErrPackage) {
		t.Fatal("executable accepted as installer", err)
	}
}

func TestPreviewReleaseCannotAuthorizeAgentAndPartialBindingsAreInvalid(t *testing.T) {
	manifest, public, key, content, now := fixture(t)
	data, err := Sign(manifest, key, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(data, []ed25519.PublicKey{public}, now, Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	if err := verified.VerifyAgent("windows", "amd64", bytes.NewReader(content)); !errors.Is(err, ErrAgentBinding) {
		t.Fatal("missing executable binding silently fell back to package", err)
	}
	payload, err := json.Marshal(manifest)
	if err != nil || bytes.Contains(payload, []byte("agent_size")) || bytes.Contains(payload, []byte("agent_sha256")) {
		t.Fatal("preview canonical encoding changed", err)
	}
	for _, binding := range []struct {
		size int64
		hash string
	}{
		{1, ""}, {0, strings.Repeat("a", 64)}, {-1, strings.Repeat("a", 64)}, {MaxPackageSize + 1, strings.Repeat("a", 64)}, {1, "bad"}, {1, strings.Repeat("A", 64)},
	} {
		candidate := manifest
		candidate.Artifacts = append([]Artifact(nil), manifest.Artifacts...)
		candidate.Artifacts[0].AgentSize = binding.size
		candidate.Artifacts[0].AgentSHA256 = binding.hash
		if _, err := Sign(candidate, key, now); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid binding was signed", err)
		}
		payload, _ := json.Marshal(candidate)
		if _, err := Verify(signedRaw(t, payload, key), []ed25519.PublicKey{public}, now, Checkpoint{}); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid authenticated binding accepted", err)
		}
	}
	for _, extra := range []string{`,"agent_size":null`, `,"agent_sha256":null`, `,"agent_size":1,"agent_size":1`, `,"AgentSize":1`} {
		malformed := bytes.Replace(payload, []byte(`"format":"msi"`), []byte(`"format":"msi"`+extra), 1)
		if _, err := Verify(signedRaw(t, malformed, key), []ed25519.PublicKey{public}, now, Checkpoint{}); !errors.Is(err, ErrInvalid) {
			t.Fatal("ambiguous binding accepted", err)
		}
	}
}
