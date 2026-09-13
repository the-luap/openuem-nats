package netbirdcommand

import (
	"strings"
	"testing"
	"time"
)

func control(kind string) ControlRequest {
	c := command()
	r := ControlRequest{Version: Version, Identity: c.Identity, RequestID: "90000000-0000-4000-8000-000000000009", Kind: kind, IssuedAt: c.IssuedAt, ExpiresAt: c.IssuedAt.Add(ControlLifetime)}
	if kind != "state" {
		r.ReferenceID = c.RequestID
		r.CommandHash, _ = c.Digest()
	}
	return r
}

func TestControlCorrelationExpiryAndStrictPayloads(t *testing.T) {
	for _, kind := range []string{"state", "receipt", "release"} {
		c := control(kind)
		data, err := EncodeControl(c)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeControl(data)
		if err != nil || decoded != c {
			t.Fatal("control round trip failed", err)
		}
		if !c.Executable(c.Identity, c.IssuedAt) || c.Executable(c.Identity, c.ExpiresAt) || c.Executable(c.Identity, c.IssuedAt.Add(-ClockAllowance-time.Nanosecond)) {
			t.Fatal("control expiry was not enforced")
		}
		r, _ := ControlResponseFor(c, "ok")
		switch kind {
		case "state":
			r.State = State{Status: "ready", Revision: strings.Repeat("a", 64), Remaining: MaxJournalAttempts}
		case "receipt", "release":
			r.Receipt, _ = ReceiptFor(command(), "unconfirmed")
			if kind == "release" {
				r.ReleaseID = c.RequestID
			}
		}
		raw, err := EncodeControlResponse(c, r)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeControlResponse(raw, c)
		if err != nil || again != r {
			t.Fatal("response round trip failed", err)
		}
		foreign := c
		foreign.RequestID = "90000000-0000-4000-8000-000000000008"
		if _, err = DecodeControlResponse(raw, foreign); err == nil {
			t.Fatal("response matched another request")
		}
		for _, field := range []string{"state", "receipt"} {
			body := strings.Replace(string(raw), `"`+field+`":{`, `"`+field+`":{"unknown":true,`, 1)
			if _, err = DecodeControlResponse([]byte(body), c); err == nil {
				t.Fatal("unknown nested field accepted")
			}
		}
		for _, body := range []string{string(raw) + string(raw), strings.Replace(string(raw), `"remaining":0`, `"remaining":0,"remaining":0`, 1)} {
			if body == string(raw) {
				continue
			}
			if _, err = DecodeControlResponse([]byte(body), c); err == nil {
				t.Fatal("ambiguous response accepted")
			}
		}
		for _, outcome := range []string{"missing", "blocked", "conflict", "unavailable"} {
			r, _ := ControlResponseFor(c, outcome)
			raw, err := EncodeControlResponse(c, r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = DecodeControlResponse(raw, c); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestControlRejectsInvalidStateAndResolution(t *testing.T) {
	for _, state := range []State{{Status: "ready", Revision: strings.Repeat("a", 64)}, {Status: "full", Revision: strings.Repeat("a", 64), Remaining: 1}, {Status: "busy", Revision: strings.Repeat("a", 64), Remaining: 10}, {Status: "unavailable", Remaining: 1}, {Status: "unconfirmed", Revision: strings.Repeat("a", 64), PendingID: command().RequestID, PendingHash: strings.Repeat("b", 64), Remaining: MaxJournalAttempts + 1}} {
		if state.Valid() {
			t.Fatal("invalid journal state accepted")
		}
	}
	c := control("release")
	for _, mutate := range []func(*ControlRequest){func(c *ControlRequest) { c.Kind = "execute" }, func(c *ControlRequest) { c.ReferenceID = "" }, func(c *ControlRequest) { c.CommandHash = "" }, func(c *ControlRequest) { c.ExpiresAt = c.ExpiresAt.Add(time.Nanosecond) }, func(c *ControlRequest) { c.Identity.SiteID = 0 }} {
		v := c
		mutate(&v)
		if v.Valid() {
			t.Fatal("invalid control accepted")
		}
	}
	data, _ := EncodeControl(control("state"))
	for _, raw := range []string{strings.Replace(string(data), `"kind":"state"`, `"kind":null`, 1), strings.Replace(string(data), `"kind":"state"`, `"kind":"state","Kind":"state"`, 1)} {
		if _, err := DecodeControl([]byte(raw)); err == nil {
			t.Fatal("ambiguous control accepted")
		}
	}
	r, _ := ControlResponseFor(c, "ok")
	r.Receipt, _ = ReceiptFor(command(), "unconfirmed")
	r.ReleaseID = "90000000-0000-4000-8000-000000000008"
	if r.Matches(c) {
		t.Fatal("different release was treated as successful")
	}
}

func TestControlReceiptRequiresRetainedExecutionEvidence(t *testing.T) {
	c := control("receipt")
	for _, status := range []string{"busy", "rejected"} {
		r, _ := ControlResponseFor(c, "ok")
		r.Receipt, _ = ReceiptFor(command(), status)
		if r.Matches(c) {
			t.Fatal("transient reply accepted as retained evidence")
		}
	}
}

func FuzzControl(f *testing.F) {
	registration := control("state")
	registration.Kind = "registration-state"
	data, _ := EncodeControl(registration)
	f.Add(data)
	for _, kind := range []string{"state", "receipt", "release"} {
		data, _ := EncodeControl(control(kind))
		f.Add(data)
	}
	f.Add([]byte(`{"version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := DecodeControl(data)
		if err != nil {
			return
		}
		encoded, err := EncodeControl(c)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeControl(encoded)
		if err != nil || again != c {
			t.Fatal("unstable control round trip", err)
		}
	})
}

func FuzzControlResponse(f *testing.F) {
	c := control("receipt")
	r, _ := ControlResponseFor(c, "ok")
	r.Receipt, _ = ReceiptFor(command(), "unconfirmed")
	data, _ := EncodeControlResponse(c, r)
	f.Add(data)
	f.Add([]byte(`{"version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := DecodeControlResponse(data, c)
		if err != nil {
			return
		}
		encoded, err := EncodeControlResponse(c, r)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeControlResponse(encoded, c)
		if err != nil || again != r {
			t.Fatal("unstable response round trip", err)
		}
	})
}
