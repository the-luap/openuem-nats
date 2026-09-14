package netbirdinstall

import (
	"encoding/json"
	"strings"
	"testing"
)

func removalFixture() Removal {
	return Removal{Schema: Schema, Platform: "macos", Architecture: "arm64", Format: "pkg", PackageID: "io.netbird.client", Version: "0.78.1", StateDigest: strings.Repeat("a", 64)}
}

func TestRemovalDescriptorIsExactSourceFreeInstalledState(t *testing.T) {
	r := removalFixture()
	data, err := EncodeRemoval(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRemoval(data)
	if err != nil || got != r {
		t.Fatal("removal descriptor did not round trip", err)
	}
	for _, field := range []string{"url", "path", "executable", "arguments", "approval_id", "setup_key", "certificate"} {
		if strings.Contains(string(data), `"`+field+`"`) {
			t.Fatal("removal included unrelated authority", field)
		}
	}
	original, err := r.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Removal){func(r *Removal) { r.Version = "0.78.2" }, func(r *Removal) { r.Architecture = "amd64" }, func(r *Removal) { r.StateDigest = strings.Repeat("b", 64) }, func(r *Removal) { r.Platform, r.Format, r.PackageID = "linux", "deb", "netbird" }} {
		changed := r
		change(&changed)
		digest, err := changed.Digest()
		if err != nil || digest == original {
			t.Fatal("changed native state retained the same descriptor digest", err)
		}
	}
}

func TestRemovalDescriptorRejectsAmbiguousOrUnrelatedTargets(t *testing.T) {
	for name, change := range map[string]func(*Removal){
		"schema": func(r *Removal) { r.Schema++ }, "windows": func(r *Removal) { r.Platform = "windows" },
		"format": func(r *Removal) { r.Format = "exe" }, "package": func(r *Removal) { r.PackageID = "other.package" },
		"path": func(r *Removal) { r.PackageID = "/Applications/NetBird.app" }, "architecture": func(r *Removal) { r.Architecture = "all" },
		"version": func(r *Removal) { r.Version = "--force" }, "empty": func(r *Removal) { r.Version = "" },
		"state": func(r *Removal) { r.StateDigest = "" }, "uppercase": func(r *Removal) { r.StateDigest = strings.Repeat("A", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			r := removalFixture()
			change(&r)
			data, _ := json.Marshal(r)
			if r.Valid() {
				t.Fatal("invalid removal was valid")
			}
			if _, err := DecodeRemoval(data); err == nil {
				t.Fatal("invalid removal decoded")
			}
		})
	}
	raw, _ := EncodeRemoval(removalFixture())
	for _, body := range []string{
		string(raw) + "{}", strings.Replace(string(raw), `"schema":1`, `"schema":1,"Schema":1`, 1),
		strings.Replace(string(raw), `"schema":1`, `"schema":1,"schema":1`, 1),
		strings.Replace(string(raw), `"schema":1`, `"schema":"1"`, 1),
		strings.Replace(string(raw), `"schema":1`, `"schema":null`, 1),
		strings.Replace(string(raw), `"schema":1`, `"schema":1,"url":"https://owned.test/file.pkg"`, 1),
		strings.Replace(string(raw), `"version":"0.78.1"`, `"version":{}`, 1),
		strings.Replace(string(raw), `"version":"0.78.1",`, ``, 1), string(raw) + strings.Repeat(" ", MaxMessage),
	} {
		if _, err := DecodeRemoval([]byte(body)); err == nil {
			t.Fatal("ambiguous removal decoded")
		}
	}
}

func FuzzRemoval(f *testing.F) {
	data, _ := EncodeRemoval(removalFixture())
	f.Add(data)
	f.Add([]byte(`{"schema":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := DecodeRemoval(data)
		if err != nil {
			return
		}
		encoded, err := EncodeRemoval(r)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeRemoval(encoded)
		if err != nil || got != r {
			t.Fatal("unstable removal descriptor", err)
		}
	})
}
