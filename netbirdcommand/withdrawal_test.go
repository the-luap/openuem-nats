package netbirdcommand

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func withdrawalControl(kind string) ControlRequest {
	c := control("receipt")
	c.Version, c.Kind = RecoveryVersion, kind
	c.Revision, c.Operation = command().Revision, command().Operation
	return c
}

func TestWithdrawalRequiresExplicitVersionAndCompleteReference(t *testing.T) {
	for _, kind := range []string{"receipt", "withdraw"} {
		c := withdrawalControl(kind)
		data, err := EncodeControl(c)
		if err != nil {
			t.Fatal(err)
		}
		v, err := DecodeControl(data)
		if err != nil || v != c {
			t.Fatal("recovery control changed", err)
		}
		for _, mutate := range []func(*ControlRequest){
			func(c *ControlRequest) { c.Version = Version },
			func(c *ControlRequest) { c.Revision = "" },
			func(c *ControlRequest) { c.Operation = "" },
			func(c *ControlRequest) { c.Operation = "install" },
			func(c *ControlRequest) { c.Kind = "release" },
			func(c *ControlRequest) { c.Kind = "state" },
		} {
			bad := c
			mutate(&bad)
			if bad.Valid() {
				t.Fatal("ambiguous recovery reference accepted")
			}
		}
		for _, raw := range []string{
			strings.Replace(string(data), `"operation":"switchprofile"`, `"operation":null`, 1),
			strings.Replace(string(data), `"operation":"switchprofile"`, `"operation":"switchprofile","Operation":"switchprofile"`, 1),
			strings.Replace(string(data), `"version":2`, `"version":1,"version":2`, 1),
			strings.Replace(string(data), `,"revision":"`+c.Revision+`"`, "", 1),
		} {
			if _, err := DecodeControl([]byte(raw)); err == nil {
				t.Fatal("incomplete or ambiguous recovery schema accepted")
			}
		}
		r, _ := ControlResponseFor(c, "ok")
		r.Receipt, _ = ReceiptFor(command(), "withdrawn")
		r.ReleaseID = c.RequestID
		wire, err := EncodeControlResponse(c, r)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeControlResponse(wire, c)
		if err != nil || again != r {
			t.Fatal("withdrawal proof changed", err)
		}
		for _, mutate := range []func(*ControlResponse){
			func(r *ControlResponse) { r.Version = Version },
			func(r *ControlResponse) { r.Receipt.Status = "unconfirmed"; r.ReleaseID = "" },
			func(r *ControlResponse) { r.Receipt.Operation = "up" },
			func(r *ControlResponse) { r.Receipt.Revision = strings.Repeat("f", 64) },
			func(r *ControlResponse) { r.ReleaseID = "" },
		} {
			bad := r
			mutate(&bad)
			if kind == "receipt" && bad.Receipt.Status == "unconfirmed" {
				continue
			}
			if bad.Matches(c) {
				t.Fatal("foreign or absent withdrawal proof accepted")
			}
		}
	}
}

func TestLegacyControlEncodingAndEvidenceRemainDistinct(t *testing.T) {
	c := control("receipt")
	data, err := EncodeControl(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"revision"`) || strings.Contains(string(data), `"operation"`) {
		t.Fatal("legacy encoding gained recovery fields")
	}
	// Freeze the original field order and digest, independent of new struct fields.
	expected := `{"version":1,"device_id":"` + c.DeviceID + `","tenant_id":1,"site_id":2,"individual":false,"certificate_hash":"","request_id":"` + c.RequestID + `","kind":"receipt","reference_id":"` + c.ReferenceID + `","command_hash":"` + c.CommandHash + `","issued_at":"` + c.IssuedAt.Format("2006-01-02T15:04:05.999999999Z07:00") + `","expires_at":"` + c.ExpiresAt.Format("2006-01-02T15:04:05.999999999Z07:00") + `"}`
	if string(data) != expected {
		t.Fatal("legacy control wire changed", string(data), expected)
	}
	sum := sha256.Sum256([]byte(expected))
	hash, _ := c.Digest()
	if hash != hex.EncodeToString(sum[:]) {
		t.Fatal("legacy control digest changed")
	}
	r, _ := ControlResponseFor(c, "ok")
	r.Receipt, _ = ReceiptFor(command(), "withdrawn")
	r.ReleaseID = c.RequestID
	if r.Matches(c) {
		t.Fatal("legacy receipt query established new recovery capability")
	}
}

func FuzzWithdrawalResponse(f *testing.F) {
	c := withdrawalControl("receipt")
	r, _ := ControlResponseFor(c, "ok")
	r.Receipt, _ = ReceiptFor(command(), "withdrawn")
	r.ReleaseID = c.RequestID
	data, _ := EncodeControlResponse(c, r)
	f.Add(data)
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := DecodeControlResponse(data, c)
		if err != nil {
			return
		}
		wire, err := EncodeControlResponse(c, r)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeControlResponse(wire, c)
		if err != nil || again != r {
			t.Fatal("unstable withdrawal response", err)
		}
	})
}
