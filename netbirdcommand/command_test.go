package netbirdcommand

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func command() Command {
	at := time.Date(2026, 9, 13, 19, 0, 0, 123456000, time.UTC)
	return Command{Version: Version, Identity: Identity{DeviceID: "owned-device", TenantID: 1, SiteID: 2}, RequestID: "90000000-0000-4000-8000-000000000001", Revision: strings.Repeat("a", 64), Operation: "switchprofile", Profile: "Office, Berlin", ManagementURL: "https://management.example.test", IssuedAt: at, ExpiresAt: at.Add(Lifetime)}
}

func TestCommandRoundTripIdentityExpiryAndReceipt(t *testing.T) {
	for _, individual := range []bool{false, true} {
		c := command()
		if individual {
			c.Individual = true
			c.DeviceID = "90000000-0000-4000-8000-000000000002"
			c.CertificateHash = strings.Repeat("b", 64)
		}
		body, err := Encode(c)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(body)
		if err != nil || got != c {
			t.Fatal("command round trip changed identity", err)
		}
		if !got.Executable(c.Identity, c.IssuedAt) || !got.Executable(c.Identity, c.IssuedAt.Add(-ClockAllowance)) || got.Executable(c.Identity, c.IssuedAt.Add(-ClockAllowance-time.Nanosecond)) || got.Executable(c.Identity, c.ExpiresAt) {
			t.Fatal("execution lifetime was not enforced")
		}
		foreign := c.Identity
		foreign.SiteID++
		if got.Executable(foreign, c.IssuedAt) {
			t.Fatal("foreign scope accepted")
		}
		for _, status := range []string{"completed", "unconfirmed", "rejected", "busy"} {
			receipt, err := ReceiptFor(c, status)
			if err != nil || !receipt.Matches(c) {
				t.Fatal("receipt did not correlate", err)
			}
			raw, err := EncodeReceipt(receipt)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeReceipt(raw)
			if err != nil || decoded != receipt {
				t.Fatal("receipt round trip failed", err)
			}
			changed := c
			changed.Profile = "other"
			if receipt.Matches(changed) {
				t.Fatal("receipt matched different command bytes")
			}
		}
		subject, err := Subject(c.DeviceID)
		if err != nil || subject != "agent.netbird.command."+c.DeviceID {
			t.Fatal("invalid subject", err)
		}
	}
}

func TestCommandRejectsMalformedOrAmbiguousWire(t *testing.T) {
	c := command()
	data, _ := Encode(c)
	body := string(data)
	cases := []string{"", "null", "[]", body + body, body + " true", strings.Repeat(" ", MaxMessage+1), strings.Replace(body, `"version":1`, `"version":1,"version":1`, 1), strings.Replace(body, `"version":1`, `"Version":1`, 1), strings.Replace(body, `"individual":false,`, "", 1), strings.Replace(body, `"individual":false`, `"individual":null`, 1), strings.Replace(body, `"profile":"Office, Berlin"`, `"profile":null`, 1), strings.Replace(body, `"site_id":2`, `"site_id":2.0`, 1), strings.Replace(body, `"version":1`, `"extra":0,"version":1`, 1), string(append(append([]byte(nil), data[:len(data)-1]...), 0xff, '}'))}
	for _, raw := range cases {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Error("invalid command accepted")
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for key := range fields {
		copy := map[string]json.RawMessage{}
		for k, v := range fields {
			copy[k] = v
		}
		delete(copy, key)
		raw, _ := json.Marshal(copy)
		if _, err := Decode(raw); err == nil {
			t.Errorf("missing field accepted: %s", key)
		}
	}
}

func TestCommandRejectsInvalidTargetsAndActions(t *testing.T) {
	mutations := []func(*Command){
		func(c *Command) { c.Version = 2 }, func(c *Command) { c.DeviceID = "foreign.*" }, func(c *Command) { c.RequestID = strings.ToUpper(c.RequestID[:8]) + "-AAAA-4000-8000-000000000001" }, func(c *Command) { c.RequestID = "00000000-0000-0000-0000-000000000000" }, func(c *Command) { c.TenantID = 0 }, func(c *Command) { c.SiteID = -1 }, func(c *Command) { c.CertificateHash = strings.Repeat("b", 64) }, func(c *Command) { c.Individual = true }, func(c *Command) { c.Revision = strings.Repeat("A", 64) }, func(c *Command) { c.ManagementURL = "http://management.example.test" }, func(c *Command) { c.ManagementURL = "https://user:secret@management.example.test" }, func(c *Command) { c.Operation = "register" }, func(c *Command) { c.Operation = "up" }, func(c *Command) { c.Profile = "" }, func(c *Command) { c.Profile = "line\nbreak" }, func(c *Command) { c.Profile = strings.Repeat("x", 257) }, func(c *Command) { c.ExpiresAt = c.IssuedAt }, func(c *Command) { c.ExpiresAt = c.ExpiresAt.Add(time.Nanosecond) },
	}
	for i, mutate := range mutations {
		c := command()
		mutate(&c)
		if c.Valid() {
			t.Errorf("invalid command accepted: %d", i)
		}
		if _, err := Encode(c); err == nil {
			t.Errorf("invalid command encoded: %d", i)
		}
	}
	for _, device := range []string{"", "foreign.device", "*", ">", strings.Repeat("a", 256)} {
		if _, err := Subject(device); err == nil {
			t.Error("unsafe subject accepted")
		}
	}
}

func TestCommandDigestNormalizesTimeButBindsEveryInput(t *testing.T) {
	c := command()
	digest, _ := c.Digest()
	same := c
	same.IssuedAt = same.IssuedAt.In(time.FixedZone("test", 3600))
	same.ExpiresAt = same.ExpiresAt.In(time.FixedZone("test", 3600))
	got, err := same.Digest()
	if err != nil || got != digest {
		t.Fatal("equivalent timestamp changed digest", err)
	}
	for _, mutate := range []func(*Command){func(c *Command) { c.DeviceID = "other" }, func(c *Command) { c.SiteID++ }, func(c *Command) { c.TenantID++ }, func(c *Command) { c.Revision = strings.Repeat("c", 64) }, func(c *Command) { c.RequestID = "90000000-0000-4000-8000-000000000003" }, func(c *Command) { c.ManagementURL = "https://other.example.test" }, func(c *Command) { c.Profile = "other" }, func(c *Command) { c.IssuedAt = c.IssuedAt.Add(time.Second) }, func(c *Command) { c.ExpiresAt = c.ExpiresAt.Add(-time.Second) }} {
		changed := c
		mutate(&changed)
		got, err := changed.Digest()
		if err != nil || got == digest {
			t.Fatal("command input missing from digest", err)
		}
	}
}

func FuzzDecodeCommand(f *testing.F) {
	data, _ := Encode(command())
	f.Add(data)
	f.Add([]byte(`{"version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Decode(data)
		if err != nil {
			return
		}
		encoded, err := Encode(c)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Decode(encoded)
		if err != nil || again != c {
			t.Fatal("unstable command round trip", err)
		}
	})
}

func TestReceiptRejectsMalformedAndMismatchedEvidence(t *testing.T) {
	c := command()
	receipt, _ := ReceiptFor(c, "completed")
	data, _ := EncodeReceipt(receipt)
	body := string(data)
	for _, raw := range []string{"", "null", body + body, strings.Replace(body, `"status":"completed"`, `"status":"completed","status":"completed"`, 1), strings.Replace(body, `"status":"completed"`, `"status":null`, 1), strings.Replace(body, `"status":"completed"`, `"status":"accepted"`, 1), strings.Replace(body, `"status":"completed"`, `"Status":"completed"`, 1), strings.Replace(body, `"status":"completed"`, `"status":"completed","output":"private"`, 1)} {
		if _, err := DecodeReceipt([]byte(raw)); err == nil {
			t.Error("malformed receipt accepted")
		}
	}
	for _, mutate := range []func(*Receipt){func(r *Receipt) { r.Version = 2 }, func(r *Receipt) { r.RequestID = "90000000-0000-4000-8000-000000000003" }, func(r *Receipt) { r.DeviceID = "other" }, func(r *Receipt) { r.Revision = strings.Repeat("b", 64) }, func(r *Receipt) { r.CommandHash = strings.Repeat("c", 64) }, func(r *Receipt) { r.Operation = "up" }} {
		changed := receipt
		mutate(&changed)
		if changed.Matches(c) {
			t.Error("unrelated receipt accepted")
		}
	}
}
