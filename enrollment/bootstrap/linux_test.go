package bootstrap

import (
	"bytes"
	"testing"

	"github.com/open-uem/nats/enrollment/artifacts"
)

func TestLinuxBootstrapBindsSignedInstallerExactArchitectureAndOrigin(t *testing.T) {
	for _, architecture := range []string{"amd64", "arm64"} {
		for _, format := range []string{"deb", "rpm"} {
			t.Run(architecture+"/"+format, func(t *testing.T) {
				f := newFixture(t)
				old, err := artifacts.Verify(f.config.ReleaseEnvelope, f.trust.ReleaseKeys, f.now, artifacts.Checkpoint{})
				if err != nil {
					t.Fatal(err)
				}
				manifest := old.Manifest()
				item := &manifest.Artifacts[0]
				item.Platform, item.Architecture, item.Format = "linux", architecture, format
				item.Filename = "openuem-agent-" + manifest.Version + "-linux-" + architecture + "." + format
				f.config.ReleaseEnvelope, err = artifacts.Sign(manifest, f.releaseKey, f.now)
				if err != nil {
					t.Fatal(err)
				}
				release, err := artifacts.Verify(f.config.ReleaseEnvelope, f.trust.ReleaseKeys, f.now, artifacts.Checkpoint{})
				if err != nil {
					t.Fatal(err)
				}
				f.config.Platform, f.config.Architecture, f.config.ReleaseDigest = "linux", architecture, release.Digest()
				f.trust.Platform, f.trust.Architecture, f.trust.Checkpoint = "linux", architecture, release.Checkpoint()
				data, err := Sign(f.config, f.bootstrapKey, f.now)
				if err != nil {
					t.Fatal(err)
				}
				verified, err := Verify(data, f.trust, f.now)
				if err != nil {
					t.Fatal(err)
				}
				if verified.Artifact() != *item || verified.Config().Invitation != f.config.Invitation || verified.Config().TenantID != f.config.TenantID || verified.Config().SiteID != f.config.SiteID || verified.DownloadURL() != f.config.Origin+"/enroll/desktop/releases/"+release.Digest()+"/linux/"+architecture {
					t.Fatal("Linux bootstrap lost approved target, origin or scope")
				}
				if err := verified.VerifyPackage(bytes.NewReader(f.content)); err != nil {
					t.Fatal(err)
				}
				for _, kind := range []string{"platform", "architecture", "origin", "release rollback"} {
					trust := f.trust
					switch kind {
					case "platform":
						trust.Platform = "windows"
					case "architecture":
						trust.Architecture = "amd64"
						if architecture == "amd64" {
							trust.Architecture = "arm64"
						}
					case "origin":
						trust.Origin = "https://foreign.example.test"
					case "release rollback":
						trust.Checkpoint.Sequence++
					}
					if _, err := Verify(data, trust, f.now); err == nil {
						t.Fatal("Linux bootstrap accepted changed authority", kind)
					}
				}
			})
		}
	}
}
