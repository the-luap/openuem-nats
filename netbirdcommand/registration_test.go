package netbirdcommand

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func registrationCommand() Command {
	now := time.Now().UTC()
	return Command{Version: RegistrationVersion, Identity: Identity{DeviceID: "owned-registration", TenantID: 1, SiteID: 2}, RequestID: uuid.NewString(), Revision: strings.Repeat("a", 64), Operation: "register", SetupKey: "owned-one-off-key", ManagementURL: "https://owned-provider.example.test", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
}

func TestRegistrationWireRequiresDistinctVersionAndKey(t *testing.T) {
	c := registrationCommand()
	data, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	if err != nil || got != c {
		t.Fatal("registration round trip failed")
	}
	receipt, err := ReceiptFor(c, "completed")
	if err != nil || !receipt.Matches(c) {
		t.Fatal("registration receipt was not correlated")
	}
	changed := c
	changed.SetupKey = "different-owned-key"
	if receipt.Matches(changed) {
		t.Fatal("receipt ignored registration credential identity")
	}
	for _, modify := range []func(*Command){func(c *Command) { c.Version = Version }, func(c *Command) { c.SetupKey = "" }, func(c *Command) { c.SetupKey = "masked****" }, func(c *Command) { c.Profile = "other-profile" }, func(c *Command) { c.Operation = "up" }, func(c *Command) { c.SetupKey = strings.Repeat("a", 513) }, func(c *Command) { c.SetupKey = "owned\nkey" }} {
		changed = c
		modify(&changed)
		if changed.Valid() {
			t.Fatal("invalid registration envelope was accepted")
		}
	}
	for _, bad := range [][]byte{bytes.Replace(data, []byte(`"setup_key":"owned-one-off-key"`), []byte(`"setup_key":null`), 1), bytes.Replace(data, []byte(`"setup_key":"owned-one-off-key",`), nil, 1), bytes.Replace(data, []byte(`"version":2`), []byte(`"version":1,"version":2`), 1), bytes.Replace(data, []byte(`"setup_key"`), []byte(`"Setup_Key"`), 1), bytes.Replace(data, []byte(`"setup_key":"owned-one-off-key"`), []byte(`"setup_key":"owned","setup_key":"owned-one-off-key"`), 1)} {
		if _, err = Decode(bad); err == nil {
			t.Fatal("ambiguous registration fields were accepted")
		}
	}
	c.Version = Version
	c.Operation = "up"
	c.SetupKey = ""
	data, err = Encode(c)
	if err != nil || bytes.Contains(data, []byte("setup_key")) {
		t.Fatal("registration changed legacy command hashes")
	}
}

func TestRegistrationReadinessIsExplicit(t *testing.T) {
	c := registrationCommand()
	control := ControlRequest{Version: Version, Identity: c.Identity, RequestID: uuid.NewString(), Kind: "registration-state", IssuedAt: c.IssuedAt, ExpiresAt: c.IssuedAt.Add(ControlLifetime)}
	data, err := EncodeControl(control)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeControl(data)
	if err != nil || got != control {
		t.Fatal("registration readiness request failed")
	}
	r, err := ControlResponseFor(control, "ok")
	if err != nil {
		t.Fatal(err)
	}
	r.State = State{Status: "ready", Revision: strings.Repeat("b", 64), Remaining: 4096}
	data, err = EncodeControlResponse(control, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeControlResponse(data, control); err != nil {
		t.Fatal(err)
	}
	control.Kind = "state"
	if r.Matches(control) {
		t.Fatal("ordinary state substituted for registration support")
	}
}
