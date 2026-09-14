package netbirdcommand

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

func removalAbsenceCommand() Command {
	c := removalRecoveryCommand()
	r := c.RemovalRecovery.Original
	c.Version, c.Operation, c.RequestID = RemovalAbsenceVersion, "verify-removal-absence", "90000000-0000-4000-8000-000000000009"
	c.RemovalAbsence = RemovalAbsence{RemovalAbsenceReference{r.RequestID, r.CommandHash, r.Revision, r.ReleaseID}, RemovalAbsenceProfile, c.RemovalRecovery.JournalRevision, strings.Repeat("e", 64)}
	c.RemovalRecovery = RemovalRecovery{}
	c.ExpiresAt = c.IssuedAt.Add(RemovalAbsenceLifetime)
	return c
}

func absenceInspection() ControlRequest {
	c := removalAbsenceCommand()
	return ControlRequest{Version: RemovalAbsenceInspectionVersion, Identity: c.Identity, RequestID: c.RequestID, Kind: "removal-absence-state", RemovalAbsenceOriginal: c.RemovalAbsence.Original, IssuedAt: c.IssuedAt, ExpiresAt: c.IssuedAt.Add(RemovalAbsenceInspectionLifetime)}
}

func absenceState(c ControlRequest, outcome string) ControlResponse {
	r, _ := ControlResponseFor(c, outcome)
	if outcome == "ok" {
		r.RemovalAbsence = removalAbsenceCommand().RemovalAbsence
		r.State = State{Status: "ready", Revision: r.RemovalAbsence.JournalRevision, Remaining: 100}
	}
	return r
}

func TestCurrentAbsenceBindsIndependentVerificationAndOriginalReference(t *testing.T) {
	c := removalAbsenceCommand()
	data, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Decode(data); err != nil || got != c {
		t.Fatal("independent absence round trip", err)
	}
	if strings.Contains(string(data), `"removal"`) || strings.Contains(string(data), `"recovery"`) || strings.Contains(string(data), `"mode"`) {
		t.Fatal("absence fabricated native original evidence")
	}
	for _, status := range []string{"completed", "unconfirmed", "rejected", "busy", "withdrawn"} {
		r, err := ReceiptFor(c, status)
		if err != nil || !r.Matches(c) {
			t.Fatal("independent receipt", err)
		}
		original := removalCommand()
		if r.Matches(original) || r.Matches(removalRecoveryCommand()) {
			t.Fatal("verification became original native success")
		}
	}
	r, _ := ReceiptFor(c, "completed")
	for name, change := range map[string]func(*Command){
		"original":        func(c *Command) { c.RemovalAbsence.Original.RequestID = "90000000-0000-4000-8000-000000000010" },
		"original-hash":   func(c *Command) { c.RemovalAbsence.Original.CommandHash = strings.Repeat("f", 64) },
		"original-review": func(c *Command) { c.RemovalAbsence.Original.Revision = strings.Repeat("f", 64) },
		"release":         func(c *Command) { c.RemovalAbsence.Original.ReleaseID = "90000000-0000-4000-8000-000000000010" },
		"current-files":   func(c *Command) { c.RemovalAbsence.StateDigest = strings.Repeat("f", 64) },
		"current-journal": func(c *Command) { c.RemovalAbsence.JournalRevision = strings.Repeat("f", 64) },
		"console-review":  func(c *Command) { c.Revision = strings.Repeat("f", 64) },
		"certificate":     func(c *Command) { c.CertificateHash = strings.Repeat("f", 64) },
		"site":            func(c *Command) { c.SiteID++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := c
			change(&changed)
			if !changed.Valid() || r.Matches(changed) {
				t.Fatal("receipt ignored changed evidence")
			}
		})
	}
	if !c.Executable(c.Identity, c.ExpiresAt.Add(-time.Nanosecond)) || c.Executable(c.Identity, c.ExpiresAt) {
		t.Fatal("verification expiry")
	}
	for _, value := range []any{c, c.RemovalAbsence, c.RemovalAbsence.Original, absenceInspection(), absenceState(absenceInspection(), "ok")} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("incidental encoding lost independent intent")
		}
	}
}

func TestCurrentAbsenceRefusesMutatingAndLegacyGrammars(t *testing.T) {
	c := removalAbsenceCommand()
	for _, change := range []func(*Command){
		func(c *Command) { c.Operation = "uninstall" },
		func(c *Command) { c.Operation = "recover-removal" },
		func(c *Command) { c.Version = RemovalRecoveryVersion },
		func(c *Command) { c.Individual = false; c.CertificateHash = "" },
		func(c *Command) { c.RequestID = c.RemovalAbsence.Original.RequestID },
		func(c *Command) { c.RequestID = c.RemovalAbsence.Original.ReleaseID },
		func(c *Command) { c.RemovalAbsence.Original.ReleaseID = c.RemovalAbsence.Original.RequestID },
		func(c *Command) { c.RemovalAbsence.Profile = "manifest" },
		func(c *Command) { c.RemovalAbsence.Profile = "macos-official-pkg-v2" },
		func(c *Command) { c.RemovalAbsence.JournalRevision = "" },
		func(c *Command) { c.RemovalAbsence.StateDigest = "" },
		func(c *Command) { c.RemovalAbsence.Original.CommandHash = "" },
		func(c *Command) { c.Removal = removalCommand().Removal },
		func(c *Command) { c.RemovalRecovery = removalRecoveryCommand().RemovalRecovery },
		func(c *Command) { c.Package = installationCommand().Package },
		func(c *Command) { c.SetupKey = "owned-key" },
		func(c *Command) { c.ManagementURL = "https://owned.test" },
		func(c *Command) { c.Profile = "owned-profile" },
		func(c *Command) { c.ExpiresAt = c.ExpiresAt.Add(time.Nanosecond) },
	} {
		bad := c
		change(&bad)
		if bad.Valid() {
			t.Fatal("mixed verification intent accepted")
		}
		if _, err := Encode(bad); err == nil {
			t.Fatal("mixed verification encoded")
		}
	}
	for _, old := range []Command{command(), installationCommand(), removalCommand(), removalRecoveryCommand()} {
		before, _ := Encode(old)
		if got, err := Decode(before); err != nil || got != old {
			t.Fatal("old grammar changed", err)
		}
		old.RemovalAbsence = c.RemovalAbsence
		if old.Valid() {
			t.Fatal("old grammar silently acquired absence")
		}
	}
	legacy := c.Identity
	legacy.Individual, legacy.CertificateHash = false, ""
	control := ControlRequest{Version: RecoveryVersion, Identity: legacy, RequestID: c.RequestID, Kind: "withdraw", ReferenceID: c.RequestID, CommandHash: strings.Repeat("a", 64), Revision: c.Revision, Operation: c.Operation, IssuedAt: c.IssuedAt, ExpiresAt: c.IssuedAt.Add(ControlLifetime)}
	if control.Valid() {
		t.Fatal("legacy identity acquired verification controls")
	}
}

func TestCurrentAbsenceInspectionRequiresExactReadyEvidence(t *testing.T) {
	c := absenceInspection()
	data, err := EncodeControl(c)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeControl(data); err != nil || got != c {
		t.Fatal("inspection round trip", err)
	}
	for _, outcome := range []string{"ok", "missing", "unavailable", "blocked", "conflict"} {
		r := absenceState(c, outcome)
		data, err := EncodeControlResponse(c, r)
		if err != nil {
			t.Fatal(outcome, err)
		}
		if got, err := DecodeControlResponse(data, c); err != nil || got != r {
			t.Fatal(outcome, err)
		}
		changed := c
		changed.RemovalAbsenceOriginal.ReleaseID = "90000000-0000-4000-8000-000000000010"
		if _, err := DecodeControlResponse(data, changed); err == nil {
			t.Fatal("inspection ignored original release")
		}
	}
	for _, change := range []func(*ControlResponse){
		func(r *ControlResponse) { r.State.Revision = strings.Repeat("f", 64) },
		func(r *ControlResponse) { r.State = State{Status: "unavailable"} },
		func(r *ControlResponse) { r.RemovalAbsence.Original.CommandHash = strings.Repeat("f", 64) },
		func(r *ControlResponse) { r.RemovalAbsence.Profile = "manifest" },
		func(r *ControlResponse) { r.Outcome = "absent" },
		func(r *ControlResponse) { r.Outcome = "unavailable" },
		func(r *ControlResponse) { r.RemovalAbsence = RemovalAbsence{} },
		func(r *ControlResponse) { r.Removal = removalCommand().Removal },
		func(r *ControlResponse) { r.RemovalRecovery = removalRecoveryCommand().RemovalRecovery },
		func(r *ControlResponse) { r.Receipt, _ = ReceiptFor(removalAbsenceCommand(), "completed") },
		func(r *ControlResponse) { r.ReleaseID = c.RemovalAbsenceOriginal.ReleaseID },
	} {
		r := absenceState(c, "ok")
		change(&r)
		if r.Matches(c) {
			t.Fatal("mixed inspection result")
		}
	}
	for _, change := range []func(*ControlRequest){
		func(c *ControlRequest) { c.Version = RemovalRecoveryInspectionVersion },
		func(c *ControlRequest) { c.Kind = "removal-recovery-state" },
		func(c *ControlRequest) { c.RemovalRecoveryOriginal = recoveryInspection().RemovalRecoveryOriginal },
		func(c *ControlRequest) { c.RemovalAbsenceOriginal = RemovalAbsenceReference{} },
		func(c *ControlRequest) { c.ReferenceID = c.RequestID },
		func(c *ControlRequest) { c.Operation = "verify-removal-absence" },
		func(c *ControlRequest) { c.Individual = false; c.CertificateHash = "" },
		func(c *ControlRequest) { c.ExpiresAt = c.ExpiresAt.Add(time.Nanosecond) },
	} {
		bad := c
		change(&bad)
		if bad.Valid() {
			t.Fatal("mixed inspection request")
		}
	}
	old := recoveryInspection()
	old.RemovalAbsenceOriginal = c.RemovalAbsenceOriginal
	if old.Valid() {
		t.Fatal("old inspection acquired a hidden reference")
	}
	old = recoveryInspection()
	result := recoveryState(old, "ok")
	result.RemovalAbsence = removalAbsenceCommand().RemovalAbsence
	if result.Matches(old) {
		t.Fatal("old inspection acquired hidden evidence")
	}
}

func TestCurrentAbsenceStrictNestedWireAndReceiptControls(t *testing.T) {
	c := removalAbsenceCommand()
	query := absenceInspection()
	command, _ := Encode(c)
	inspection, _ := EncodeControl(query)
	response, _ := EncodeControlResponse(query, absenceState(query, "ok"))
	for _, entry := range []struct {
		data   []byte
		decode func([]byte) error
	}{
		{command, func(b []byte) error { _, err := Decode(b); return err }},
		{inspection, func(b []byte) error { _, err := DecodeControl(b); return err }},
		{response, func(b []byte) error { _, err := DecodeControlResponse(b, query); return err }},
	} {
		for _, bad := range [][]byte{
			append(append([]byte{}, entry.data...), []byte(` {}`)...),
			bytes.Replace(entry.data, []byte(`"version":`), []byte(`"Version":`), 1),
			bytes.Replace(entry.data, []byte(`"original":{`), []byte(`"original":{"removal":{},`), 1),
			bytes.Replace(entry.data, []byte(`"release_id":`), []byte(`"Release_ID":`), 1),
			bytes.Replace(entry.data, []byte(`"release_id":`), []byte(`"release_id":"90000000-0000-4000-8000-000000000005","release_id":`), 1),
			bytes.Replace(entry.data, []byte(`"original":{`), []byte(`"original":null,"discarded":{`), 1),
			append([]byte(`{"overflow":"`), bytes.Repeat([]byte("a"), MaxMessage)...),
		} {
			if entry.decode(bad) == nil {
				t.Fatal("ambiguous or foreign absence wire accepted")
			}
		}
	}
	hash, _ := c.Digest()
	for _, kind := range []string{"receipt", "withdraw"} {
		q := ControlRequest{Version: RecoveryVersion, Identity: c.Identity, RequestID: "90000000-0000-4000-8000-000000000010", Kind: kind, ReferenceID: c.RequestID, CommandHash: hash, Revision: c.Revision, Operation: c.Operation, IssuedAt: c.IssuedAt, ExpiresAt: c.IssuedAt.Add(ControlLifetime)}
		r, _ := ControlResponseFor(q, "ok")
		r.Receipt, _ = ReceiptFor(c, "withdrawn")
		r.ReleaseID = q.RequestID
		data, err := EncodeControlResponse(q, r)
		if err != nil {
			t.Fatal("owned verification control", err)
		}
		if got, err := DecodeControlResponse(data, q); err != nil || got != r {
			t.Fatal("owned control round trip", err)
		}
		q.Operation = "recover-removal"
		if r.Matches(q) {
			t.Fatal("verification control became mutating recovery")
		}
	}
}

func FuzzCurrentRemovalAbsence(f *testing.F) {
	c := removalAbsenceCommand()
	q := absenceInspection()
	command, _ := Encode(c)
	inspection, _ := EncodeControl(q)
	response, _ := EncodeControlResponse(q, absenceState(q, "ok"))
	for _, seed := range [][]byte{command, inspection, response, []byte(`{}`), []byte(`null`)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if c, err := Decode(data); err == nil {
			encoded, err := Encode(c)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := Decode(encoded); err != nil || got != c {
				t.Fatal("unstable command", err)
			}
			if c.Version == RemovalAbsenceVersion && (c.Operation != "verify-removal-absence" || c.Removal != (packageapi.Removal{}) || c.RemovalRecovery != (RemovalRecovery{})) {
				t.Fatal("absence acquired mutation")
			}
		}
		if c, err := DecodeControl(data); err == nil {
			encoded, err := EncodeControl(c)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := DecodeControl(encoded); err != nil || got != c {
				t.Fatal("unstable query", err)
			}
		}
		if r, err := DecodeControlResponse(data, q); err == nil {
			encoded, err := EncodeControlResponse(q, r)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := DecodeControlResponse(encoded, q); err != nil || got != r {
				t.Fatal("unstable response", err)
			}
		}
	})
}
