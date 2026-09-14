package artifacts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

func TestLinuxInstallerFormatsBindExactPackageAgentAndCheckpoint(t *testing.T) {
	for _, architecture := range []string{"amd64", "arm64"} {
		for _, format := range []string{"deb", "rpm"} {
			t.Run(architecture+"/"+format, func(t *testing.T) {
				manifest, public, private, content, now := fixture(t)
				item := &manifest.Artifacts[0]
				item.Platform, item.Architecture, item.Format = "linux", architecture, format
				item.Filename = "openuem-agent-" + manifest.Version + "-linux-" + architecture + "." + format
				agent := []byte("owned non-executable Linux agent fixture")
				hash := sha256.Sum256(agent)
				item.AgentSize, item.AgentSHA256 = int64(len(agent)), hex.EncodeToString(hash[:])
				data, err := Sign(manifest, private, now)
				if err != nil {
					t.Fatal(err)
				}
				verified, err := Verify(data, []ed25519.PublicKey{public}, now, Checkpoint{})
				if err != nil {
					t.Fatal(err)
				}
				if err := verified.VerifyPackage("linux", architecture, bytes.NewReader(content)); err != nil {
					t.Fatal(err)
				}
				if err := verified.VerifyAgent("linux", architecture, bytes.NewReader(agent)); err != nil {
					t.Fatal(err)
				}
				if err := verified.VerifyAgent("linux", architecture, bytes.NewReader(content)); !errors.Is(err, ErrAgentBinding) {
					t.Fatal("package hash substituted for executable binding", err)
				}
				checkpoint := verified.Checkpoint()
				manifest.Sequence--
				older, err := Sign(manifest, private, now)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Verify(older, []ed25519.PublicKey{public}, now, checkpoint); !errors.Is(err, ErrRollback) {
					t.Fatal("Linux release rolled back a durable checkpoint", err)
				}
			})
		}
	}
}

func TestLinuxManifestRejectsAliasesForeignFormatsAndAmbiguousPackages(t *testing.T) {
	for _, kind := range []string{"platform case", "architecture alias", "shell", "archive", "pkg", "msi", "both package formats"} {
		t.Run(kind, func(t *testing.T) {
			manifest, public, private, _, now := fixture(t)
			item := &manifest.Artifacts[0]
			item.Platform, item.Architecture, item.Format = "linux", "amd64", "deb"
			switch kind {
			case "platform case":
				item.Platform = "Linux"
			case "architecture alias":
				item.Architecture = "x86_64"
			case "shell":
				item.Format = "sh"
			case "archive":
				item.Format = "tar.gz"
			case "pkg", "msi":
				item.Format = kind
			}
			item.Filename = "openuem-agent-" + manifest.Version + "-" + item.Platform + "-" + item.Architecture + "." + item.Format
			if kind == "both package formats" {
				other := *item
				other.Format = "rpm"
				other.Filename = "openuem-agent-" + manifest.Version + "-linux-amd64.rpm"
				manifest.Artifacts = append(manifest.Artifacts, other)
			}
			if _, err := Sign(manifest, private, now); !errors.Is(err, ErrInvalid) {
				t.Fatal("unsafe Linux artifact was signed", err)
			}
			// Exercise validation of a correctly signed hostile payload as well.
			payload, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(signedRaw(t, payload, private), []ed25519.PublicKey{public}, now, Checkpoint{}); !errors.Is(err, ErrInvalid) {
				t.Fatal("signed unsafe Linux artifact was accepted", err)
			}
		})
	}
}
