package netbirdcommand

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

func removalStageCleanupCommand() Command {
	c := removalRecoveryCommand()
	r := c.RemovalRecovery.Original
	c.Version, c.Operation, c.RequestID = RemovalStageCleanupVersion, "cleanup-removal-stage", "90000000-0000-4000-8000-000000000009"
	c.RemovalStageCleanup = RemovalStageCleanup{RemovalStageCleanupReference{r.RequestID, r.CommandHash, r.Revision, r.ReleaseID}, RemovalStageCleanupProfile, c.RemovalRecovery.JournalRevision, strings.Repeat("e", 64), 7, true, 128}
	c.RemovalRecovery = RemovalRecovery{}
	c.ExpiresAt = c.IssuedAt.Add(RemovalStageCleanupLifetime)
	return c
}

func stageCleanupInspection() ControlRequest {
	c := removalStageCleanupCommand()
	return ControlRequest{Version: RemovalStageCleanupInspectionVersion, Identity: c.Identity, RequestID: c.RequestID, Kind: "removal-stage-cleanup-state", RemovalStageCleanupOriginal: c.RemovalStageCleanup.Original, IssuedAt: c.IssuedAt, ExpiresAt: c.IssuedAt.Add(RemovalStageCleanupInspectionLifetime)}
}

func stageCleanupState(c ControlRequest, outcome string) ControlResponse {
	r, _ := ControlResponseFor(c, outcome)
	if outcome == "ok" {
		r.RemovalStageCleanup = removalStageCleanupCommand().RemovalStageCleanup
		r.State = State{Status: "ready", Revision: r.RemovalStageCleanup.JournalRevision, Remaining: 100}
	}
	return r
}

func TestRemovalStageCleanupBindsIndependentMutationAndOriginalReference(t *testing.T) {
	c := removalStageCleanupCommand()
	data, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Decode(data); err != nil || got != c {
		t.Fatal("independent stage cleanup round trip", err)
	}
	if strings.Contains(string(data), `"removal"`) || strings.Contains(string(data), `"recovery"`) || strings.Contains(string(data), `"mode"`) {
		t.Fatal("stage cleanup fabricated native original evidence")
	}
	for _, status := range []string{"completed", "unconfirmed", "rejected", "busy", "withdrawn"} {
		r, err := ReceiptFor(c, status)
		if err != nil || !r.Matches(c) {
			t.Fatal("independent receipt", err)
		}
		original := removalCommand()
		if r.Matches(original) || r.Matches(removalRecoveryCommand()) || r.Matches(removalAbsenceCommand()) {
			t.Fatal("cleanup became original native success")
		}
	}
	r, _ := ReceiptFor(c, "completed")
	for name, change := range map[string]func(*Command){
		"original":        func(c *Command) { c.RemovalStageCleanup.Original.RequestID = "90000000-0000-4000-8000-000000000010" },
		"original-hash":   func(c *Command) { c.RemovalStageCleanup.Original.CommandHash = strings.Repeat("f", 64) },
		"original-review": func(c *Command) { c.RemovalStageCleanup.Original.Revision = strings.Repeat("f", 64) },
		"release":         func(c *Command) { c.RemovalStageCleanup.Original.ReleaseID = "90000000-0000-4000-8000-000000000010" },
		"current-files":   func(c *Command) { c.RemovalStageCleanup.StateDigest = strings.Repeat("f", 64) },
		"current-journal": func(c *Command) { c.RemovalStageCleanup.JournalRevision = strings.Repeat("f", 64) },
		"console-review":  func(c *Command) { c.Revision = strings.Repeat("f", 64) },
		"directory-count": func(c *Command) { c.RemovalStageCleanup.DirectoryCount-- },
		"manifest-bytes":  func(c *Command) { c.RemovalStageCleanup.ManifestBytes++ },
		"manifest-presence": func(c *Command) {
			c.RemovalStageCleanup.ManifestPresent = false
			c.RemovalStageCleanup.ManifestBytes = 0
		},
		"certificate": func(c *Command) { c.CertificateHash = strings.Repeat("f", 64) },
		"site":        func(c *Command) { c.SiteID++ },
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
		t.Fatal("cleanup expiry")
	}
	for _, value := range []any{c, c.RemovalStageCleanup, c.RemovalStageCleanup.Original, stageCleanupInspection(), stageCleanupState(stageCleanupInspection(), "ok")} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("incidental encoding lost independent intent")
		}
	}
}

func TestRemovalStageCleanupRefusesMutatingAndLegacyGrammars(t *testing.T) {
	c := removalStageCleanupCommand()
	for _, change := range []func(*Command){
		func(c *Command) { c.Operation = "uninstall" },
		func(c *Command) { c.Operation = "verify-removal-absence" },
		func(c *Command) { c.RemovalAbsence = removalAbsenceCommand().RemovalAbsence },
		func(c *Command) { c.RemovalStageCleanup.DirectoryCount = 0 },
		func(c *Command) { c.RemovalStageCleanup.DirectoryCount = 8 },
		func(c *Command) { c.RemovalStageCleanup.ManifestBytes = -1 },
		func(c *Command) { c.RemovalStageCleanup.ManifestBytes = (2 << 20) + 1 },
		func(c *Command) { c.RemovalStageCleanup.ManifestPresent = false },
		func(c *Command) { c.Operation = "recover-removal" },
		func(c *Command) { c.Version = RemovalRecoveryVersion },
		func(c *Command) { c.Individual = false; c.CertificateHash = "" },
		func(c *Command) { c.RequestID = c.RemovalStageCleanup.Original.RequestID },
		func(c *Command) { c.RequestID = c.RemovalStageCleanup.Original.ReleaseID },
		func(c *Command) { c.RemovalStageCleanup.Original.ReleaseID = c.RemovalStageCleanup.Original.RequestID },
		func(c *Command) { c.RemovalStageCleanup.Profile = "manifest" },
		func(c *Command) { c.RemovalStageCleanup.Profile = "macos-official-pkg-v2" },
		func(c *Command) { c.RemovalStageCleanup.JournalRevision = "" },
		func(c *Command) { c.RemovalStageCleanup.StateDigest = "" },
		func(c *Command) { c.RemovalStageCleanup.Original.CommandHash = "" },
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
			t.Fatal("mixed cleanup intent accepted")
		}
		if _, err := Encode(bad); err == nil {
			t.Fatal("mixed cleanup encoded")
		}
	}
	for _, old := range []Command{command(), installationCommand(), removalCommand(), removalRecoveryCommand(), removalAbsenceCommand()} {
		before, _ := Encode(old)
		if got, err := Decode(before); err != nil || got != old {
			t.Fatal("old grammar changed", err)
		}
		old.RemovalStageCleanup = c.RemovalStageCleanup
		if old.Valid() {
			t.Fatal("old grammar silently acquired stage cleanup")
		}
	}
	legacy := c.Identity
	legacy.Individual, legacy.CertificateHash = false, ""
	control := ControlRequest{Version: RecoveryVersion, Identity: legacy, RequestID: c.RequestID, Kind: "withdraw", ReferenceID: c.RequestID, CommandHash: strings.Repeat("a", 64), Revision: c.Revision, Operation: c.Operation, IssuedAt: c.IssuedAt, ExpiresAt: c.IssuedAt.Add(ControlLifetime)}
	if control.Valid() {
		t.Fatal("legacy identity acquired cleanup controls")
	}
}

func TestRemovalStageCleanupInspectionRequiresExactReadyEvidence(t *testing.T) {
	c := stageCleanupInspection()
	data, err := EncodeControl(c)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeControl(data); err != nil || got != c {
		t.Fatal("inspection round trip", err)
	}
	for _, outcome := range []string{"ok", "missing", "unavailable", "blocked", "conflict"} {
		r := stageCleanupState(c, outcome)
		data, err := EncodeControlResponse(c, r)
		if err != nil {
			t.Fatal(outcome, err)
		}
		if got, err := DecodeControlResponse(data, c); err != nil || got != r {
			t.Fatal(outcome, err)
		}
		changed := c
		changed.RemovalStageCleanupOriginal.ReleaseID = "90000000-0000-4000-8000-000000000010"
		if _, err := DecodeControlResponse(data, changed); err == nil {
			t.Fatal("inspection ignored original release")
		}
	}
	for _, change := range []func(*ControlResponse){
		func(r *ControlResponse) { r.State.Revision = strings.Repeat("f", 64) },
		func(r *ControlResponse) { r.State = State{Status: "unavailable"} },
		func(r *ControlResponse) { r.RemovalStageCleanup.Original.CommandHash = strings.Repeat("f", 64) },
		func(r *ControlResponse) { r.RemovalStageCleanup.Profile = "manifest" },
		func(r *ControlResponse) { r.Outcome = "absent" },
		func(r *ControlResponse) { r.Outcome = "unavailable" },
		func(r *ControlResponse) { r.RemovalStageCleanup = RemovalStageCleanup{} },
		func(r *ControlResponse) { r.Removal = removalCommand().Removal },
		func(r *ControlResponse) { r.RemovalAbsence = removalAbsenceCommand().RemovalAbsence },
		func(r *ControlResponse) { r.RemovalRecovery = removalRecoveryCommand().RemovalRecovery },
		func(r *ControlResponse) { r.Receipt, _ = ReceiptFor(removalStageCleanupCommand(), "completed") },
		func(r *ControlResponse) { r.ReleaseID = c.RemovalStageCleanupOriginal.ReleaseID },
	} {
		r := stageCleanupState(c, "ok")
		change(&r)
		if r.Matches(c) {
			t.Fatal("mixed inspection result")
		}
	}
	for _, change := range []func(*ControlRequest){
		func(c *ControlRequest) { c.Version = RemovalRecoveryInspectionVersion },
		func(c *ControlRequest) { c.RemovalAbsenceOriginal = absenceInspection().RemovalAbsenceOriginal },
		func(c *ControlRequest) { c.Version = RemovalAbsenceInspectionVersion },
		func(c *ControlRequest) { c.Kind = "removal-recovery-state" },
		func(c *ControlRequest) { c.RemovalRecoveryOriginal = recoveryInspection().RemovalRecoveryOriginal },
		func(c *ControlRequest) { c.RemovalStageCleanupOriginal = RemovalStageCleanupReference{} },
		func(c *ControlRequest) { c.ReferenceID = c.RequestID },
		func(c *ControlRequest) { c.Operation = "cleanup-removal-stage" },
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
	old.RemovalStageCleanupOriginal = c.RemovalStageCleanupOriginal
	if old.Valid() {
		t.Fatal("old inspection acquired a hidden reference")
	}
	old = recoveryInspection()
	result := recoveryState(old, "ok")
	result.RemovalStageCleanup = removalStageCleanupCommand().RemovalStageCleanup
	if result.Matches(old) {
		t.Fatal("old inspection acquired hidden evidence")
	}
}

func TestRemovalStageCleanupStrictNestedWireAndReceiptControls(t *testing.T) {
	c := removalStageCleanupCommand()
	query := stageCleanupInspection()
	command, _ := Encode(c)
	inspection, _ := EncodeControl(query)
	response, _ := EncodeControlResponse(query, stageCleanupState(query, "ok"))
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
				t.Fatal("ambiguous or foreign stage cleanup wire accepted")
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
			t.Fatal("owned cleanup control", err)
		}
		if got, err := DecodeControlResponse(data, q); err != nil || got != r {
			t.Fatal("owned control round trip", err)
		}
		q.Operation = "recover-removal"
		if r.Matches(q) {
			t.Fatal("cleanup control became mutating recovery")
		}
	}
}

func FuzzRemovalStageCleanup(f *testing.F) {
	c := removalStageCleanupCommand()
	q := stageCleanupInspection()
	command, _ := Encode(c)
	inspection, _ := EncodeControl(q)
	response, _ := EncodeControlResponse(q, stageCleanupState(q, "ok"))
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
			if c.Version == RemovalStageCleanupVersion && (c.Operation != "cleanup-removal-stage" || c.Removal != (packageapi.Removal{}) || c.RemovalRecovery != (RemovalRecovery{}) || c.RemovalAbsence != (RemovalAbsence{})) {
				t.Fatal("cleanup acquired another operation")
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

func TestRemovalStageCleanupRequiresCompleteBoundedSummaryOnWire(t *testing.T) {
	c, q := removalStageCleanupCommand(), stageCleanupInspection()
	descriptor, err := EncodeRemovalStageCleanup(c.RemovalStageCleanup)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"directory_count", "manifest_present", "manifest_bytes"} {
		for _, change := range []string{"missing", "null", "duplicate", "alias", "type"} {
			var data map[string]json.RawMessage
			if json.Unmarshal(descriptor, &data) != nil {
				t.Fatal("fixture")
			}
			original := data[field]
			switch change {
			case "missing":
				delete(data, field)
			case "null":
				data[field] = json.RawMessage("null")
			case "alias":
				data[strings.ToUpper(field)] = data[field]
				delete(data, field)
			case "type":
				data[field] = json.RawMessage(`"0"`)
			}
			changed, _ := json.Marshal(data)
			if change == "duplicate" {
				changed = append([]byte(`{"`+field+`":`+string(original)+`,`), changed[1:]...)
			}
			if _, err := DecodeRemovalStageCleanup(changed); err == nil {
				t.Fatal("ambiguous cleanup summary", field, change)
			}
		}
	}
	for _, old := range []ControlRequest{absenceInspection(), recoveryInspection()} {
		c := old
		c.RemovalStageCleanupOriginal = q.RemovalStageCleanupOriginal
		if c.Valid() {
			t.Fatal("old control accepted hidden cleanup reference")
		}
		var p ControlResponse
		if old.Version == RemovalAbsenceInspectionVersion {
			p = absenceState(old, "ok")
		} else {
			p = recoveryState(old, "ok")
		}
		p.RemovalStageCleanup = removalStageCleanupCommand().RemovalStageCleanup
		if p.Matches(old) {
			t.Fatal("old response accepted hidden cleanup summary")
		}
	}
	for _, manifest := range []struct {
		present bool
		size    int64
	}{{false, 0}, {true, 0}, {true, 2 << 20}} {
		r := c.RemovalStageCleanup
		r.ManifestPresent, r.ManifestBytes = manifest.present, manifest.size
		data, err := EncodeRemovalStageCleanup(r)
		if err != nil {
			t.Fatal("valid bounded cleanup summary", err)
		}
		if got, err := DecodeRemovalStageCleanup(data); err != nil || got != r {
			t.Fatal("summary round trip", err)
		}
	}
}
