package netbirdcommand

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

func removalCommand() Command {
	c := installationCommand()
	c.Version, c.Operation, c.Package = RemovalVersion, "uninstall", packageapi.Package{}
	c.Removal = packageapi.Removal{Schema: 1, Platform: "macos", Architecture: "arm64", Format: "pkg", PackageID: "io.netbird.client", Version: "0.78.1", StateDigest: strings.Repeat("a", 64)}
	c.ExpiresAt = c.IssuedAt.Add(RemovalLifetime)
	return c
}

func TestRemovalCommandBindsInspectedStateAndCurrentIndividualIdentity(t *testing.T) {
	c := removalCommand()
	data, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	if err != nil || got != c {
		t.Fatal("removal command did not round trip", err)
	}
	for _, field := range []string{"management_url", "profile", "setup_key", "package", "url", "path"} {
		if strings.Contains(string(data), `"`+field+`"`) {
			t.Fatal("removal includes unrelated intent", field)
		}
	}
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("incidental serialization silently discarded the removal")
	}
	if !c.Executable(c.Identity, c.IssuedAt) || !c.Executable(c.Identity, c.ExpiresAt.Add(-time.Nanosecond)) || c.Executable(c.Identity, c.ExpiresAt) {
		t.Fatal("removal execution expiry is not exact")
	}
	r, err := ReceiptFor(c, "completed")
	if err != nil || !r.Matches(c) {
		t.Fatal("removal receipt did not correlate", err)
	}
	encoded, err := EncodeReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeReceipt(encoded); err != nil || got != r {
		t.Fatal("removal receipt did not round trip", err)
	}
	for name, change := range map[string]func(*Command){
		"state":           func(c *Command) { c.Removal.StateDigest = strings.Repeat("f", 64) },
		"package-version": func(c *Command) { c.Removal.Version = "0.78.2" },
		"architecture":    func(c *Command) { c.Removal.Architecture = "amd64" },
		"identity":        func(c *Command) { c.CertificateHash = strings.Repeat("d", 64) },
		"organization":    func(c *Command) { c.TenantID++ }, "site": func(c *Command) { c.SiteID++ },
		"request": func(c *Command) { c.RequestID = "90000000-0000-4000-8000-000000000004" },
		"review":  func(c *Command) { c.Revision = strings.Repeat("e", 64) },
		"expiry":  func(c *Command) { c.ExpiresAt = c.ExpiresAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := c
			change(&changed)
			if !changed.Valid() || r.Matches(changed) {
				t.Fatal("receipt ignored changed removal")
			}
		})
	}
	foreign := c.Identity
	foreign.CertificateHash = strings.Repeat("d", 64)
	if c.Executable(foreign, c.IssuedAt) {
		t.Fatal("renewed identity admitted old removal")
	}
}

func TestRemovalCommandRejectsMixedOperationsAndLegacySchemas(t *testing.T) {
	for name, change := range map[string]func(*Command){
		"legacy":             func(c *Command) { c.Individual = false; c.CertificateHash = "" },
		"connection-version": func(c *Command) { c.Version = Version }, "registration-version": func(c *Command) { c.Version = RegistrationVersion },
		"installation-version": func(c *Command) { c.Version = InstallationVersion }, "future": func(c *Command) { c.Version++ },
		"operation": func(c *Command) { c.Operation = "install" }, "package": func(c *Command) { c.Package = installationCommand().Package },
		"profile": func(c *Command) { c.Profile = "owned-profile" }, "provider": func(c *Command) { c.ManagementURL = "https://owned.test" },
		"credential": func(c *Command) { c.SetupKey = "owned-key" }, "state": func(c *Command) { c.Removal.StateDigest = "invalid" },
		"deadline": func(c *Command) { c.ExpiresAt = c.ExpiresAt.Add(time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			c := removalCommand()
			change(&c)
			if c.Valid() {
				t.Fatal("invalid removal accepted")
			}
			if _, err := Encode(c); err == nil {
				t.Fatal("invalid removal encoded")
			}
		})
	}
	for _, c := range []Command{command(), installationCommand()} {
		c.Removal = removalCommand().Removal
		if c.Valid() {
			t.Fatal("older operation acquired hidden removal intent")
		}
	}
	data, _ := Encode(removalCommand())
	for _, body := range []string{
		string(data) + "{}", strings.Replace(string(data), `"version":4`, `"version":4,"version":4`, 1),
		strings.Replace(string(data), `"removal":{`, `"removal":null,"alias":{`, 1),
		strings.Replace(string(data), `"removal":{`, `"removal":{"url":"https://owned.test/file.pkg",`, 1),
		strings.Replace(string(data), `"state_digest":`, `"State_Digest":`, 1),
		strings.Replace(string(data), `"operation":"uninstall"`, `"operation":"uninstall","profile":""`, 1),
	} {
		if _, err := Decode([]byte(body)); err == nil {
			t.Fatal("ambiguous removal decoded")
		}
	}
}

func TestRemovalRecoveryRequiresExactCommandAndIndividualRecipient(t *testing.T) {
	original := removalCommand()
	for _, kind := range []string{"receipt", "withdraw"} {
		c := withdrawalControl(kind)
		c.Identity = original.Identity
		c.ReferenceID = original.RequestID
		c.CommandHash, _ = original.Digest()
		c.Revision = original.Revision
		c.Operation = "uninstall"
		data, err := EncodeControl(c)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := DecodeControl(data); err != nil || got != c {
			t.Fatal("removal recovery did not round trip", err)
		}
		r, _ := ControlResponseFor(c, "ok")
		status := "unconfirmed"
		if kind == "withdraw" {
			status = "withdrawn"
			r.ReleaseID = c.RequestID
		}
		r.Receipt, _ = ReceiptFor(original, status)
		wire, err := EncodeControlResponse(c, r)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := DecodeControlResponse(wire, c); err != nil || got != r {
			t.Fatal("removal proof did not correlate", err)
		}
		changed := c
		changed.Operation = "install"
		if r.Matches(changed) {
			t.Fatal("removal proof matched installation")
		}
		c.Individual = false
		c.CertificateHash = ""
		if c.Valid() {
			t.Fatal("legacy recipient acquired removal recovery")
		}
	}
	c := control("receipt")
	c.Identity = original.Identity
	c.ReferenceID = original.RequestID
	c.CommandHash, _ = original.Digest()
	r, _ := ControlResponseFor(c, "ok")
	r.Receipt, _ = ReceiptFor(original, "unconfirmed")
	if !r.Matches(c) {
		t.Fatal("original receipt read failed")
	}
	c.Individual = false
	c.CertificateHash = ""
	r, _ = ControlResponseFor(c, "ok")
	r.Receipt, _ = ReceiptFor(original, "unconfirmed")
	if r.Matches(c) {
		t.Fatal("legacy receipt reader accepted native removal evidence")
	}
}

func FuzzRemovalCommand(f *testing.F) {
	data, _ := Encode(removalCommand())
	f.Add(data)
	f.Add([]byte(`{"version":4}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Decode(data)
		if err != nil {
			return
		}
		encoded, err := Encode(c)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(encoded)
		if err != nil || got != c {
			t.Fatal("unstable removal command", err)
		}
	})
}

func TestRemovalPreservesVersionThreeInstallationWire(t *testing.T) {
	c := installationCommand()
	want := `{"version":3,"device_id":"90000000-0000-4000-8000-000000000002","tenant_id":1,"site_id":2,"individual":true,"certificate_hash":"` + strings.Repeat("b", 64) + `","request_id":"90000000-0000-4000-8000-000000000001","revision":"` + strings.Repeat("a", 64) + `","operation":"install","package":{"schema":1,"approval_id":"90000000-0000-4000-8000-000000000003","tenant_id":1,"platform":"linux","architecture":"arm64","format":"deb","package_id":"netbird","version":"0.78.1","url":"https://packages.example.test/netbird.deb?private=owned-source","size":1234,"sha256":"` + strings.Repeat("c", 64) + `"},"issued_at":"2026-09-13T19:00:00.123456Z","expires_at":"2026-09-13T19:10:00.123456Z"}`
	data, err := Encode(c)
	if err != nil || string(data) != want {
		t.Fatal("version-three installation wire changed", err)
	}
}
