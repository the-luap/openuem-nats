package netbirdcommand

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

func installationCommand() Command {
	c := command()
	c.Version, c.Operation, c.ManagementURL, c.Profile = InstallationVersion, "install", "", ""
	c.Individual, c.DeviceID, c.CertificateHash = true, "90000000-0000-4000-8000-000000000002", strings.Repeat("b", 64)
	c.Package = packageapi.Package{Schema: 1, ApprovalID: "90000000-0000-4000-8000-000000000003", TenantID: c.TenantID, Platform: "linux", Architecture: "arm64", Format: "deb", PackageID: "netbird", Version: "0.78.1", URL: "https://packages.example.test/netbird.deb?private=owned-source", Size: 1234, SHA256: strings.Repeat("c", 64)}
	c.ExpiresAt = c.IssuedAt.Add(InstallationLifetime)
	return c
}

func TestInstallationWireIdentityLifetimePrivacyAndCorrelation(t *testing.T) {
	c := installationCommand()
	data, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	if err != nil || got != c {
		t.Fatal("installation round trip failed", err)
	}
	for _, field := range []string{"management_url", "profile", "setup_key"} {
		if bytes.Contains(data, []byte(`"`+field+`"`)) {
			t.Fatalf("installation encoded unrelated field: %s", field)
		}
	}
	if !bytes.Contains(data, []byte("owned-source")) {
		t.Fatal("explicit codec omitted the approved source")
	}
	if raw, err := json.Marshal(c); err == nil || bytes.Contains(raw, []byte("owned-source")) {
		t.Fatal("incidental serialization exposed or discarded the source")
	}
	if strings.Contains(fmt.Sprintf("%s %v %+v %#v", c, c, c, c), "owned-source") {
		t.Fatal("diagnostic formatting exposed the source")
	}
	if !c.Executable(c.Identity, c.IssuedAt) || !c.Executable(c.Identity, c.ExpiresAt.Add(-time.Nanosecond)) || c.Executable(c.Identity, c.ExpiresAt) {
		t.Fatal("installation lifetime boundary changed")
	}
	foreign := c.Identity
	foreign.CertificateHash = strings.Repeat("d", 64)
	if c.Executable(foreign, c.IssuedAt) {
		t.Fatal("a renewed or foreign certificate admitted the old command")
	}
	r, err := ReceiptFor(c, "completed")
	if err != nil || !r.Matches(c) {
		t.Fatal("installation receipt did not correlate", err)
	}
	encoded, err := EncodeReceipt(r)
	if err != nil || bytes.Contains(encoded, []byte("owned-source")) {
		t.Fatal("receipt contains package source", err)
	}
	if decoded, err := DecodeReceipt(encoded); err != nil || decoded != r {
		t.Fatal("installation receipt round trip failed", err)
	}
	for name, mutate := range map[string]func(*Command){
		"approval":     func(c *Command) { c.Package.ApprovalID = "90000000-0000-4000-8000-000000000004" },
		"source":       func(c *Command) { c.Package.URL += "-changed" },
		"version":      func(c *Command) { c.Package.Version = "0.78.2" },
		"bytes":        func(c *Command) { c.Package.SHA256 = strings.Repeat("d", 64) },
		"size":         func(c *Command) { c.Package.Size++ },
		"architecture": func(c *Command) { c.Package.Architecture = "amd64" },
		"format": func(c *Command) {
			c.Package.Format = "rpm"
			c.Package.URL = "https://packages.example.test/netbird.rpm"
		},
		"organization": func(c *Command) { c.TenantID++; c.Package.TenantID++ },
		"site":         func(c *Command) { c.SiteID++ },
		"device":       func(c *Command) { c.DeviceID = "90000000-0000-4000-8000-000000000005" },
		"certificate":  func(c *Command) { c.CertificateHash = strings.Repeat("e", 64) },
		"revision":     func(c *Command) { c.Revision = strings.Repeat("f", 64) },
		"expiry":       func(c *Command) { c.ExpiresAt = c.ExpiresAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := c
			mutate(&changed)
			if !changed.Valid() || r.Matches(changed) {
				t.Fatal("receipt ignored changed installation intent")
			}
		})
	}
}

func TestInstallationRejectsLegacyIdentityMixedIntentAndInvalidPackage(t *testing.T) {
	for name, mutate := range map[string]func(*Command){
		"legacy":             func(c *Command) { c.Individual = false; c.CertificateHash = "" },
		"old-version":        func(c *Command) { c.Version = RegistrationVersion },
		"unknown-version":    func(c *Command) { c.Version++ },
		"connection":         func(c *Command) { c.Operation = "up" },
		"removal":            func(c *Command) { c.Operation = "uninstall" },
		"provider":           func(c *Command) { c.ManagementURL = "https://management.example.test" },
		"profile":            func(c *Command) { c.Profile = "Office" },
		"credential":         func(c *Command) { c.SetupKey = "owned-key" },
		"other-organization": func(c *Command) { c.Package.TenantID++ },
		"empty-package":      func(c *Command) { c.Package = packageapi.Package{} },
		"windows":            func(c *Command) { c.Package.Platform = "windows" },
		"invalid-hash":       func(c *Command) { c.Package.SHA256 = strings.Repeat("A", 64) },
		"extra-lifetime":     func(c *Command) { c.ExpiresAt = c.ExpiresAt.Add(time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			c := installationCommand()
			mutate(&c)
			if c.Valid() {
				t.Fatal("invalid installation intent accepted")
			}
			if _, err := Encode(c); err == nil {
				t.Fatal("invalid installation intent encoded")
			}
		})
	}
	for _, c := range []Command{command(), registrationCommand()} {
		c.Package = installationCommand().Package
		if c.Valid() {
			t.Fatal("earlier command accepted hidden package intent")
		}
	}
}

func TestInstallationStrictNestedSchema(t *testing.T) {
	data, _ := Encode(installationCommand())
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatal(err)
	}
	var pkg map[string]json.RawMessage
	if err := json.Unmarshal(top["package"], &pkg); err != nil {
		t.Fatal(err)
	}
	for _, fields := range []map[string]json.RawMessage{top, pkg} {
		for key, value := range fields {
			for _, replacement := range []string{"missing", "null", "false", "[]", "{}"} {
				if replacement == "missing" {
					delete(fields, key)
				} else {
					fields[key] = json.RawMessage(replacement)
				}
				var raw []byte
				if _, nested := fields["schema"]; nested || key == "schema" {
					p, _ := json.Marshal(fields)
					raw = bytes.Replace(data, top["package"], p, 1)
				} else {
					raw, _ = json.Marshal(fields)
				}
				if _, err := Decode(raw); err == nil {
					t.Fatalf("accepted invalid %s field %s", replacement, key)
				}
				fields[key] = value
			}
		}
	}
	for _, oldNew := range [][2]string{
		{`"version":3`, `"version":1,"version":3`},
		{`"version":3`, `"Version":3`},
		{`"package":`, `"Package":`},
		{`"schema":1`, `"schema":1,"schema":1`},
		{`"schema":1`, `"Schema":1`},
		{`"size":1234`, `"size":1234.0`},
		{`"size":1234`, `"size":1234,"ignored":"private"`},
		{`"operation":"install"`, `"operation":"install","setup_key":""`},
		{`"operation":"install"`, `"operation":"install","profile":""`},
		{`"operation":"install"`, `"operation":"install","management_url":""`},
	} {
		if raw := bytes.Replace(data, []byte(oldNew[0]), []byte(oldNew[1]), 1); bytes.Equal(raw, data) {
			t.Fatal("malformed fixture did not change")
		} else if _, err := Decode(raw); err == nil {
			t.Fatal("ambiguous installation payload accepted")
		}
	}
}

func TestInstallationRecoveryUsesCurrentIndividualIdentity(t *testing.T) {
	c := installationCommand()
	hash, _ := c.Digest()
	q := ControlRequest{Version: RecoveryVersion, Identity: c.Identity, RequestID: "90000000-0000-4000-8000-000000000006", Kind: "withdraw", ReferenceID: c.RequestID, CommandHash: hash, Revision: c.Revision, Operation: c.Operation, IssuedAt: c.IssuedAt, ExpiresAt: c.IssuedAt.Add(ControlLifetime)}
	r, err := ControlResponseFor(q, "ok")
	if err != nil {
		t.Fatal(err)
	}
	r.Receipt, _ = ReceiptFor(c, "withdrawn")
	r.ReleaseID = q.RequestID
	raw, err := EncodeControlResponse(q, r)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeControlResponse(raw, q); err != nil || got != r {
		t.Fatal("installation withdrawal round trip failed", err)
	}
	q.Individual, q.CertificateHash = false, ""
	if q.Valid() || r.Matches(q) {
		t.Fatal("shared identity accepted privileged installation recovery")
	}
	q.Version, q.Kind, q.Revision, q.Operation = Version, "receipt", "", ""
	r, err = ControlResponseFor(q, "ok")
	if err != nil {
		t.Fatal(err)
	}
	r.Receipt, _ = ReceiptFor(c, "unconfirmed")
	if r.Matches(q) {
		t.Fatal("old control request accepted installation evidence for a shared identity")
	}
}

func TestInstallationDoesNotChangeEarlierCanonicalWire(t *testing.T) {
	c := command()
	// Captures the established version-one field order, explicit empty/false
	// values and timestamp formatting independently of the current encoder.
	want := `{"version":1,"device_id":"owned-device","tenant_id":1,"site_id":2,"individual":false,"certificate_hash":"","request_id":"90000000-0000-4000-8000-000000000001","revision":"` + strings.Repeat("a", 64) + `","operation":"switchprofile","management_url":"https://management.example.test","profile":"Office, Berlin","issued_at":"2026-09-13T19:00:00.123456Z","expires_at":"2026-09-13T19:02:00.123456Z"}`
	for _, registration := range []bool{false, true} {
		if registration {
			c.Version, c.Operation, c.Profile, c.SetupKey = RegistrationVersion, "register", "", "owned-key"
			want = strings.Replace(want, `"version":1`, `"version":2`, 1)
			want = strings.Replace(want, `"operation":"switchprofile"`, `"operation":"register"`, 1)
			want = strings.Replace(want, `"profile":"Office, Berlin"`, `"profile":"","setup_key":"owned-key"`, 1)
		}
		raw, err := Encode(c)
		if err != nil || string(raw) != want {
			t.Fatal("earlier canonical command changed", err)
		}
		sum := sha256.Sum256([]byte(want))
		if got, err := c.Digest(); err != nil || got != hex.EncodeToString(sum[:]) {
			t.Fatal("earlier immutable command hash changed", err)
		}
	}
}
