package netbirdcommand

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

func removalInspection() ControlRequest {
	c := removalCommand()
	return ControlRequest{Version: RemovalInspectionVersion, Identity: c.Identity, RequestID: c.RequestID, Kind: "removal-state", IssuedAt: c.IssuedAt, ExpiresAt: c.IssuedAt.Add(RemovalInspectionLifetime)}
}

func removalStateResponse(c ControlRequest, outcome string) ControlResponse {
	r, _ := ControlResponseFor(c, outcome)
	if outcome == "ok" || outcome == "absent" {
		r.State = State{Status: "ready", Revision: strings.Repeat("a", 64), Remaining: 100}
	}
	if outcome == "ok" {
		r.Removal = removalCommand().Removal
	}
	return r
}

func TestRemovalInspectionDistinguishesCurrentPresenceAbsenceAndUnavailable(t *testing.T) {
	c := removalInspection()
	data, err := EncodeControl(c)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeControl(data); err != nil || got != c {
		t.Fatal("inspection did not round trip", err)
	}
	if !c.Executable(c.Identity, c.ExpiresAt.Add(-time.Nanosecond)) || c.Executable(c.Identity, c.ExpiresAt) {
		t.Fatal("inspection deadline ignored")
	}
	for _, outcome := range []string{"ok", "absent", "unavailable", "blocked", "conflict"} {
		r := removalStateResponse(c, outcome)
		data, err := EncodeControlResponse(c, r)
		if err != nil {
			t.Fatal(outcome, err)
		}
		if got, err := DecodeControlResponse(data, c); err != nil || got != r {
			t.Fatal("inspection response did not round trip", outcome, err)
		}
		if strings.Contains(string(data), `"receipt"`) || strings.Contains(string(data), `"release_id"`) {
			t.Fatal("inspection manufactured execution evidence")
		}
		if _, err := json.Marshal(r); err == nil {
			t.Fatal("incidental JSON dropped inspection fields")
		}
		foreign := c
		foreign.CertificateHash = strings.Repeat("f", 64)
		if _, err := DecodeControlResponse(data, foreign); err == nil {
			t.Fatal("foreign current identity accepted inspection")
		}
	}
	for _, change := range []func(*ControlRequest){
		func(c *ControlRequest) { c.Version = Version }, func(c *ControlRequest) { c.Version = RecoveryVersion },
		func(c *ControlRequest) { c.Individual = false; c.CertificateHash = "" }, func(c *ControlRequest) { c.Kind = "release" },
		func(c *ControlRequest) { c.ReferenceID = c.RequestID }, func(c *ControlRequest) { c.CommandHash = strings.Repeat("a", 64) },
		func(c *ControlRequest) { c.Operation = "uninstall" }, func(c *ControlRequest) { c.Revision = strings.Repeat("a", 64) },
		func(c *ControlRequest) { c.ExpiresAt = c.ExpiresAt.Add(time.Nanosecond) },
	} {
		bad := c
		change(&bad)
		if bad.Valid() {
			t.Fatal("invalid or legacy inspection accepted")
		}
	}
}

func TestRemovalInspectionRejectsMixedStaleAndAmbiguousEvidence(t *testing.T) {
	c := removalInspection()
	for _, change := range []func(*ControlResponse){
		func(r *ControlResponse) { r.Version = Version }, func(r *ControlResponse) { r.Kind = "state" },
		func(r *ControlResponse) { r.State = State{Status: "unavailable"} }, func(r *ControlResponse) { r.Removal = packageapi.Removal{} },
		func(r *ControlResponse) { r.Outcome = "absent" }, func(r *ControlResponse) { r.Outcome = "missing" },
		func(r *ControlResponse) { r.Outcome = "unavailable" }, func(r *ControlResponse) { r.Receipt, _ = ReceiptFor(removalCommand(), "completed") },
		func(r *ControlResponse) { r.ReleaseID = c.RequestID }, func(r *ControlResponse) { r.RequestHash = strings.Repeat("f", 64) },
	} {
		r := removalStateResponse(c, "ok")
		change(&r)
		if r.Matches(c) {
			t.Fatal("invalid inspection matched")
		}
	}
	data, _ := EncodeControlResponse(c, removalStateResponse(c, "ok"))
	for _, body := range []string{
		string(data) + "{}", strings.Replace(string(data), `"version":3`, `"version":3,"Version":3`, 1),
		strings.Replace(string(data), `"removal":{`, `"removal":{"package_id":"other",`, 1),
		strings.Replace(string(data), `"removal":{`, `"removal":{"url":"https://owned.test/secret",`, 1),
		strings.Replace(string(data), `"state":{`, `"state":{"unknown":true,`, 1),
		strings.Replace(string(data), `"kind":"removal-state"`, `"kind":"removal-state","receipt":{}`, 1),
	} {
		if _, err := DecodeControlResponse([]byte(body), c); err == nil {
			t.Fatal("ambiguous inspection decoded")
		}
	}
	absent, _ := EncodeControlResponse(c, removalStateResponse(c, "absent"))
	for _, replacement := range []string{`"removal":null`, `"removal":{"schema":0}`, `"removal":[]`} {
		if _, err := DecodeControlResponse([]byte(strings.Replace(string(absent), `"removal":{}`, replacement, 1)), c); err == nil {
			t.Fatal("invalid empty inspection accepted")
		}
	}
	legacy := control("state")
	r, _ := ControlResponseFor(legacy, "ok")
	r.State = removalStateResponse(c, "ok").State
	r.Removal = removalCommand().Removal
	if r.Matches(legacy) {
		t.Fatal("old journal state advertised removal capability")
	}
}

func FuzzRemovalInspectionResponse(f *testing.F) {
	c := removalInspection()
	for _, outcome := range []string{"ok", "absent", "unavailable"} {
		data, _ := EncodeControlResponse(c, removalStateResponse(c, outcome))
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := DecodeControlResponse(data, c)
		if err != nil {
			return
		}
		encoded, err := EncodeControlResponse(c, r)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeControlResponse(encoded, c)
		if err != nil || got != r {
			t.Fatal("unstable inspection response", err)
		}
	})
}
