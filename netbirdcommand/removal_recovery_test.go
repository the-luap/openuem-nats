package netbirdcommand

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

func removalRecoveryCommand() Command {
	c := removalCommand()
	hash, _ := c.Digest()
	original := RemovalRecoveryReference{c.RequestID, hash, c.Revision, "90000000-0000-4000-8000-000000000005", c.Removal}
	c.Version, c.Operation, c.Removal = RemovalRecoveryVersion, "recover-removal", packageapi.Removal{}
	c.RequestID = "90000000-0000-4000-8000-000000000006"
	c.RemovalRecovery = RemovalRecovery{original, "manifest", strings.Repeat("c", 64), strings.Repeat("d", 64)}
	return c
}

func recoveryInspection() ControlRequest {
	c := removalRecoveryCommand()
	return ControlRequest{Version: RemovalRecoveryInspectionVersion, Identity: c.Identity, RequestID: c.RequestID, Kind: "removal-recovery-state", RemovalRecoveryOriginal: c.RemovalRecovery.Original, IssuedAt: c.IssuedAt, ExpiresAt: c.IssuedAt.Add(RemovalRecoveryInspectionLifetime)}
}

func recoveryState(c ControlRequest, outcome string) ControlResponse {
	r, _ := ControlResponseFor(c, outcome)
	if outcome == "ok" {
		r.RemovalRecovery = removalRecoveryCommand().RemovalRecovery
		r.State = State{Status: "ready", Revision: r.RemovalRecovery.JournalRevision, Remaining: 100}
	}
	return r
}

func TestNativeRecoveryBindsOriginalReleaseCurrentReviewAndNewAttempt(t *testing.T) {
	c := removalRecoveryCommand()
	data, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Decode(data); err != nil || got != c {
		t.Fatal("recovery command round trip", err)
	}
	r, err := ReceiptFor(c, "unconfirmed")
	if err != nil || !r.Matches(c) {
		t.Fatal("recovery receipt", err)
	}
	for name, change := range map[string]func(*Command){
		"original-id":           func(c *Command) { c.RemovalRecovery.Original.RequestID = "90000000-0000-4000-8000-000000000008" },
		"original-hash":         func(c *Command) { c.RemovalRecovery.Original.CommandHash = strings.Repeat("e", 64) },
		"original-review":       func(c *Command) { c.RemovalRecovery.Original.Revision = strings.Repeat("e", 64) },
		"release":               func(c *Command) { c.RemovalRecovery.Original.ReleaseID = "90000000-0000-4000-8000-000000000008" },
		"original-native-state": func(c *Command) { c.RemovalRecovery.Original.Removal.StateDigest = strings.Repeat("e", 64) },
		"current-native-state":  func(c *Command) { c.RemovalRecovery.StateDigest = strings.Repeat("e", 64) },
		"journal":               func(c *Command) { c.RemovalRecovery.JournalRevision = strings.Repeat("e", 64) },
		"review":                func(c *Command) { c.Revision = strings.Repeat("e", 64) },
		"certificate":           func(c *Command) { c.CertificateHash = strings.Repeat("e", 64) },
		"request":               func(c *Command) { c.RequestID = "90000000-0000-4000-8000-000000000008" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := c
			change(&changed)
			if !changed.Valid() || r.Matches(changed) {
				t.Fatal("receipt ignored changed recovery")
			}
		})
	}
	if !c.Executable(c.Identity, c.ExpiresAt.Add(-time.Nanosecond)) || c.Executable(c.Identity, c.ExpiresAt) {
		t.Fatal("recovery expiry")
	}
	for _, value := range []any{c, c.RemovalRecovery, c.RemovalRecovery.Original, recoveryInspection(), recoveryState(recoveryInspection(), "ok")} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("incidental serialization lost recovery intent")
		}
	}
	for _, old := range []Command{command(), installationCommand(), removalCommand()} {
		old.RemovalRecovery = c.RemovalRecovery
		if old.Valid() {
			t.Fatal("old grammar acquired hidden recovery")
		}
	}
	for _, change := range []func(*Command){
		func(c *Command) { c.RequestID = c.RemovalRecovery.Original.RequestID },
		func(c *Command) { c.RequestID = c.RemovalRecovery.Original.ReleaseID },
		func(c *Command) { c.RemovalRecovery.Mode = "absent" },
		func(c *Command) { c.RemovalRecovery.Mode = "fresh" },
		func(c *Command) { c.RemovalRecovery.JournalRevision = "" },
		func(c *Command) { c.RemovalRecovery.Original.ReleaseID = "" },
		func(c *Command) { c.Removal = removalCommand().Removal },
		func(c *Command) { c.Package = installationCommand().Package },
		func(c *Command) { c.Individual = false; c.CertificateHash = "" },
		func(c *Command) { c.ManagementURL = "https://owned.test" },
		func(c *Command) { c.SetupKey = "owned-key" },
		func(c *Command) { c.Profile = "owned-profile" },
		func(c *Command) { c.Operation = "uninstall" },
		func(c *Command) { c.Version = RemovalVersion },
		func(c *Command) { c.ExpiresAt = c.ExpiresAt.Add(time.Nanosecond) },
	} {
		bad := c
		change(&bad)
		if bad.Valid() {
			t.Fatal("invalid recovery accepted")
		}
		if _, err := Encode(bad); err == nil {
			t.Fatal("invalid recovery encoded")
		}
	}
}

func TestNativeRecoveryInspectionRequiresExactReleasedOriginalAndReadyJournal(t *testing.T) {
	c := recoveryInspection()
	data, err := EncodeControl(c)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeControl(data); err != nil || got != c {
		t.Fatal("inspection round trip", err)
	}
	for _, outcome := range []string{"ok", "missing", "blocked", "conflict", "unavailable"} {
		r := recoveryState(c, outcome)
		data, err := EncodeControlResponse(c, r)
		if err != nil {
			t.Fatal(outcome, err)
		}
		if got, err := DecodeControlResponse(data, c); err != nil || got != r {
			t.Fatal(outcome, err)
		}
		changed := c
		changed.RemovalRecoveryOriginal.ReleaseID = "90000000-0000-4000-8000-000000000009"
		if _, err := DecodeControlResponse(data, changed); err == nil {
			t.Fatal("response ignored release")
		}
	}
	for _, change := range []func(*ControlResponse){
		func(r *ControlResponse) { r.State.Revision = strings.Repeat("e", 64) },
		func(r *ControlResponse) { r.State = State{Status: "unavailable"} },
		func(r *ControlResponse) { r.RemovalRecovery.Original.CommandHash = strings.Repeat("e", 64) },
		func(r *ControlResponse) { r.RemovalRecovery.Original.Removal.Version = "0.78.2" },
		func(r *ControlResponse) { r.Outcome = "absent" },
		func(r *ControlResponse) { r.Outcome = "unavailable" },
		func(r *ControlResponse) { r.RemovalRecovery = RemovalRecovery{} },
		func(r *ControlResponse) { r.Removal = removalCommand().Removal },
		func(r *ControlResponse) { r.Receipt, _ = ReceiptFor(removalCommand(), "unconfirmed") },
		func(r *ControlResponse) { r.ReleaseID = c.RemovalRecoveryOriginal.ReleaseID },
	} {
		r := recoveryState(c, "ok")
		change(&r)
		if r.Matches(c) {
			t.Fatal("mixed recovery evidence accepted")
		}
	}
	for _, change := range []func(*ControlRequest){
		func(c *ControlRequest) { c.Version = RemovalInspectionVersion },
		func(c *ControlRequest) { c.Kind = "removal-state" },
		func(c *ControlRequest) { c.ReferenceID = c.RequestID },
		func(c *ControlRequest) { c.CommandHash = strings.Repeat("a", 64) },
		func(c *ControlRequest) { c.Revision = strings.Repeat("a", 64) },
		func(c *ControlRequest) { c.Operation = "uninstall" },
		func(c *ControlRequest) { c.Individual = false; c.CertificateHash = "" },
		func(c *ControlRequest) { c.ExpiresAt = c.ExpiresAt.Add(time.Nanosecond) },
	} {
		bad := c
		change(&bad)
		if bad.Valid() {
			t.Fatal("invalid inspection accepted")
		}
	}
	for _, old := range []ControlRequest{control("state"), withdrawalControl("receipt"), removalInspection()} {
		r, _ := ControlResponseFor(old, "unavailable")
		r.RemovalRecovery = removalRecoveryCommand().RemovalRecovery
		if r.Matches(old) {
			t.Fatal("old response advertised recovery")
		}
		old.RemovalRecoveryOriginal = c.RemovalRecoveryOriginal
		if old.Valid() {
			t.Fatal("old request acquired recovery")
		}
	}
}

func TestNativeRecoveryRejectsAmbiguousNestedWireEvidence(t *testing.T) {
	c := recoveryInspection()
	command, _ := Encode(removalRecoveryCommand())
	request, _ := EncodeControl(c)
	response, _ := EncodeControlResponse(c, recoveryState(c, "ok"))
	for _, fixture := range []struct {
		data   []byte
		decode func([]byte) error
	}{
		{command, func(b []byte) error { _, err := Decode(b); return err }},
		{request, func(b []byte) error { _, err := DecodeControl(b); return err }},
		{response, func(b []byte) error { _, err := DecodeControlResponse(b, c); return err }},
	} {
		for _, body := range []string{
			string(fixture.data) + "{}",
			strings.Replace(string(fixture.data), `"original":{`, `"original":{"Release_ID":"ignored",`, 1),
			strings.Replace(string(fixture.data), `"original":{`, `"original":{"release_id":null,`, 1),
			strings.Replace(string(fixture.data), `"removal":{`, `"removal":{"url":"https://owned.test",`, 1),
			strings.Replace(string(fixture.data), `"state_digest":`, `"State_Digest":`, 1),
			strings.Replace(string(fixture.data), `"release_id":`, `"unknown":`, 1),
		} {
			if fixture.decode([]byte(body)) == nil {
				t.Fatal("ambiguous recovery decoded")
			}
		}
	}
	empty, _ := EncodeControlResponse(c, recoveryState(c, "missing"))
	for _, replacement := range []string{`"recovery":null`, `"recovery":[]`, `"recovery":{"mode":""}`} {
		if _, err := DecodeControlResponse([]byte(strings.Replace(string(empty), `"recovery":{}`, replacement, 1)), c); err == nil {
			t.Fatal("noncanonical empty recovery")
		}
	}
}

func FuzzNativeRemovalRecovery(f *testing.F) {
	c := recoveryInspection()
	command, _ := Encode(removalRecoveryCommand())
	f.Add(command)
	request, _ := EncodeControl(c)
	f.Add(request)
	for _, outcome := range []string{"ok", "missing", "unavailable"} {
		data, _ := EncodeControlResponse(c, recoveryState(c, outcome))
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if v, err := Decode(data); err == nil {
			b, err := Encode(v)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := Decode(b); err != nil || got != v {
				t.Fatal("unstable command")
			}
		}
		if v, err := DecodeControl(data); err == nil {
			b, err := EncodeControl(v)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := DecodeControl(b); err != nil || got != v {
				t.Fatal("unstable control")
			}
		}
		if v, err := DecodeControlResponse(data, c); err == nil {
			b, err := EncodeControlResponse(c, v)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := DecodeControlResponse(b, c); err != nil || got != v {
				t.Fatal("unstable response")
			}
		}
	})
}
