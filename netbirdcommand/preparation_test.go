package netbirdcommand

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func preparationRequest() PreparationRequest {
	c := installationCommand()
	return PreparationRequest{PreparationVersion, c.Identity, c.RequestID, c.Revision, strings.Repeat("e", 64), c.Package, c.IssuedAt, c.ExpiresAt}
}

func TestPreparationExactCorrelationAndPrivateSource(t *testing.T) {
	p := preparationRequest()
	raw, err := EncodePreparation(p)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodePreparation(raw); err != nil || got != p {
		t.Fatal("preparation round trip failed", err)
	}
	if !bytes.Contains(raw, []byte("owned-source")) {
		t.Fatal("explicit encoding lost private source")
	}
	if b, err := json.Marshal(p); err == nil || bytes.Contains(b, []byte("owned-source")) {
		t.Fatal("incidental JSON exposed preparation")
	}
	if strings.Contains(fmt.Sprintf("%s %v %+v %#v", p, p, p, p), "owned-source") {
		t.Fatal("formatting leaked source")
	}
	if !p.Executable(p.Identity, p.IssuedAt) || p.Executable(p.Identity, p.ExpiresAt) {
		t.Fatal("invalid lifetime boundary")
	}
	for _, outcome := range []string{"prepared", "blocked", "conflict", "unavailable"} {
		r, err := PreparationResponseFor(p, outcome)
		if err != nil {
			t.Fatal(err)
		}
		b, err := EncodePreparationResponse(p, r)
		if err != nil || bytes.Contains(b, []byte("owned-source")) {
			t.Fatal("private response", err)
		}
		if got, err := DecodePreparationResponse(b, p); err != nil || got != r {
			t.Fatal("response round trip", err)
		}
		if _, err := DecodeReceipt(b); err == nil {
			t.Fatal("preparation became execution evidence")
		}
		for _, mutate := range []func(*PreparationRequest){
			func(p *PreparationRequest) { p.SiteID++ },
			func(p *PreparationRequest) { p.TenantID++; p.Package.TenantID++ },
			func(p *PreparationRequest) { p.CertificateHash = strings.Repeat("f", 64) },
			func(p *PreparationRequest) { p.RequestID = "90000000-0000-4000-8000-000000000007" },
			func(p *PreparationRequest) { p.Revision = strings.Repeat("f", 64) },
			func(p *PreparationRequest) { p.JournalRevision = strings.Repeat("f", 64) },
			func(p *PreparationRequest) { p.Package.URL += "-changed" },
			func(p *PreparationRequest) { p.Package.ApprovalID = "90000000-0000-4000-8000-000000000008" },
			func(p *PreparationRequest) { p.ExpiresAt = p.ExpiresAt.Add(-time.Second) },
		} {
			changed := p
			mutate(&changed)
			if !changed.Valid() || r.Matches(changed) {
				t.Fatal("response ignored changed authority")
			}
		}
	}
}

func TestPreparationStrictSchemaAndIndividualCapability(t *testing.T) {
	p := preparationRequest()
	raw, _ := EncodePreparation(p)
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("fixture")
	}
	for key, original := range fields {
		delete(fields, key)
		b, _ := json.Marshal(fields)
		if _, err := DecodePreparation(b); err == nil {
			t.Fatalf("missing field accepted: %s", key)
		}
		fields[key] = json.RawMessage("null")
		b, _ = json.Marshal(fields)
		if _, err := DecodePreparation(b); err == nil {
			t.Fatalf("null field accepted: %s", key)
		}
		fields[key] = original
	}
	for _, pair := range [][2]string{
		{`"version":1`, `"version":1,"version":1`},
		{`"version":1`, `"Version":1`},
		{`"version":1`, `"version":1,"operation":"install"`},
		{`"schema":1`, `"schema":1,"schema":1`},
		{`"package":`, `"Package":`},
	} {
		b := bytes.Replace(raw, []byte(pair[0]), []byte(pair[1]), 1)
		if bytes.Equal(b, raw) {
			t.Fatal("unchanged malformed fixture")
		}
		if _, err := DecodePreparation(b); err == nil {
			t.Fatal("ambiguous preparation accepted")
		}
	}
	for _, mutate := range []func(*PreparationRequest){
		func(p *PreparationRequest) { p.Individual = false; p.CertificateHash = "" },
		func(p *PreparationRequest) { p.Version++ },
		func(p *PreparationRequest) { p.Package.TenantID++ },
		func(p *PreparationRequest) { p.JournalRevision = "" },
		func(p *PreparationRequest) { p.ExpiresAt = p.ExpiresAt.Add(time.Nanosecond) },
	} {
		changed := p
		mutate(&changed)
		if changed.Valid() {
			t.Fatal("invalid preparation accepted")
		}
	}
	c := ControlRequest{Version: Version, Identity: p.Identity, RequestID: p.RequestID, Kind: "preparation-state", IssuedAt: p.IssuedAt, ExpiresAt: p.IssuedAt.Add(ControlLifetime)}
	data, err := EncodeControl(c)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeControl(data); err != nil || got != c {
		t.Fatal("capability round trip", err)
	}
	c.Individual, c.CertificateHash = false, ""
	if c.Valid() {
		t.Fatal("shared identity advertised package preparation")
	}
	if subject, err := PreparationSubject(p.DeviceID); err != nil || subject != "agent.netbird.prepare."+p.DeviceID {
		t.Fatal("invalid exact subject")
	}
	if _, err := PreparationSubject("legacy-device"); err == nil {
		t.Fatal("legacy preparation subject")
	}
}

func FuzzPreparationDecode(f *testing.F) {
	raw, _ := EncodePreparation(preparationRequest())
	f.Add(raw)
	f.Add([]byte(`{"version":1,"package":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := DecodePreparation(data)
		if err != nil {
			return
		}
		b, err := EncodePreparation(p)
		if err != nil {
			t.Fatal("accepted request cannot encode")
		}
		if got, err := DecodePreparation(b); err != nil || got != p {
			t.Fatal("unstable canonical request")
		}
	})
}
