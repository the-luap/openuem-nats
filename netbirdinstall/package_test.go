package netbirdinstall

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func ownedPackage() Package {
	return Package{Schema: Schema, ApprovalID: "10000000-0000-4000-8000-000000000001", TenantID: 1, Platform: "linux", Architecture: "amd64", Format: "deb", PackageID: "netbird", Version: "0.77.1-1", URL: "https://packages.example.test/netbird.deb?source=private", Size: 123, SHA256: strings.Repeat("a", 64)}
}
func TestPackageIdentityAndExactCodec(t *testing.T) {
	for _, platform := range []string{"linux", "macos"} {
		for _, arch := range []string{"amd64", "arm64", "386"} {
			for _, format := range []string{"deb", "rpm", "pkg"} {
				p := ownedPackage()
				p.Platform = platform
				p.Architecture = arch
				p.Format = format
				p.URL = "https://packages.example.test/netbird." + format
				if platform == "macos" {
					p.PackageID = "io.netbird.client"
				}
				valid := platform == "linux" && (format == "deb" || format == "rpm") || platform == "macos" && format == "pkg" && arch != "386"
				if valid != p.Valid() {
					t.Fatal("target policy mismatch", platform, arch, format)
				}
				if !valid {
					continue
				}
				data, err := Encode(p)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := Decode(data)
				if err != nil {
					t.Fatal(err)
				}
				if p != decoded {
					t.Fatal("package changed during decode")
				}
				if !decoded.MatchesTarget(1, platform, arch) {
					t.Fatal("matching target refused")
				}
				if decoded.MatchesTarget(2, platform, arch) {
					t.Fatal("foreign organization accepted")
				}
				digest, err := p.Digest()
				if err != nil {
					t.Fatal(err)
				}
				p.ApprovalID = "20000000-0000-4000-8000-000000000002"
				other, err := p.Digest()
				if err != nil {
					t.Fatal(err)
				}
				if digest == other {
					t.Fatal("approval identity missing from digest")
				}
			}
		}
	}
	p := ownedPackage()
	if strings.Contains(fmt.Sprintf("%v %#v", p, p), "private") {
		t.Fatal("source exposed in formatting")
	}
	_, err := json.Marshal(p)
	if err == nil {
		t.Fatal("invalid package accepted")
	}
}
func TestPackageRejectsInvalidSourceAndIdentity(t *testing.T) {
	mutations := []func(*Package){func(p *Package) { p.Schema = 2 }, func(p *Package) { p.ApprovalID = "00000000-0000-0000-0000-000000000000" }, func(p *Package) { p.TenantID = 0 }, func(p *Package) { p.Platform = "windows" }, func(p *Package) { p.PackageID = "another-package" }, func(p *Package) { p.Size = 0 }, func(p *Package) { p.Size = MaxPackageSize + 1 }, func(p *Package) { p.SHA256 = strings.Repeat("A", 64) }, func(p *Package) { p.Version = "--option" }, func(p *Package) { p.Version = "version\nnew" }, func(p *Package) { p.Version = "1;touch /tmp/marker" }}
	for i, change := range mutations {
		p := ownedPackage()
		change(&p)
		if p.Valid() {
			t.Fatal("invalid field accepted", i)
		}
		_, err := Encode(p)
		if err == nil {
			t.Fatal("invalid package accepted")
		}
	}
	for _, source := range []string{"http://example.test/a.deb", "https://user:secret@example.test/a.deb", "https://example.test/a.deb#fragment", "https://example.test:0/a.deb", "https://example.test:65536/a.deb", "https://example.test:0443/a.deb", "https://example.test/a.rpm", "https://example.test/a.deb?", " https://example.test/a.deb", "https://example.test/a.deb\n", "https:///a.deb"} {
		p := ownedPackage()
		p.URL = source
		if p.Valid() {
			t.Fatal("invalid source accepted", source)
		}
	}
}
func TestPackageDecodeStrictFields(t *testing.T) {
	good, err := Encode(ownedPackage())
	if err != nil {
		t.Fatal(err)
	}
	s := string(good)
	for _, bad := range []string{s + "{}", strings.Replace(s, `"schema":1`, `"schema":1,"schema":1`, 1), strings.Replace(s, `"schema":1`, `"Schema":1`, 1), strings.Replace(s, `"schema":1`, `"schema":null`, 1), strings.Replace(s, `"schema":1`, `"schema":1.0`, 1), strings.Replace(s, `"schema":1,`, "", 1), strings.Replace(s, `"schema":1`, `"schema":1,"extra":"x"`, 1), strings.Replace(s, `"size":123`, `"size":"123"`, 1), strings.Replace(s, `"size":123`, `"size":[]`, 1), "null", "[]", strings.Repeat(" ", MaxMessage+1), string([]byte{0xff})} {
		_, err := Decode([]byte(bad))
		if err == nil {
			t.Fatal("invalid JSON accepted", bad)
		}
	}
}
func FuzzPackageDecode(f *testing.F) {
	data, _ := Encode(ownedPackage())
	f.Add(data)
	f.Add([]byte(`{"schema":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Decode(data)
		if err != nil {
			return
		}
		encoded, err := Encode(p)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Decode(encoded)
		if err != nil || again != p {
			t.Fatal("round trip changed package")
		}
	})
}
