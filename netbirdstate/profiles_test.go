package netbirdstate

import (
	"reflect"
	"strings"
	"testing"

	nats "github.com/open-uem/nats"
)

func TestProfileIdentityStorage(t *testing.T) {
	profiles := []nats.NetbirdProfile{{ID: "default", Name: "office, with spaces", Active: true}, {ID: "a1b2c3d4", Name: "duplicate"}, {ID: "b1b2c3d4", Name: "duplicate"}, {Name: "legacy, comma"}}
	encoded, err := Encode(nats.Netbird{ProfileDetails: profiles, Profiles: []string{"ignored legacy projection"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(encoded)
	if err != nil || !reflect.DeepEqual(got, profiles) {
		t.Fatal("profile identities did not round trip")
	}
	if got[0].Handle() != "default" || got[0].Label() != "office, with spaces (default)" || got[3].Handle() != "legacy, comma" {
		t.Fatal("labels changed handles")
	}
	encoded, err = Encode(nats.Netbird{Profiles: []string{"legacy, comma"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err = Decode(encoded)
	if err != nil || len(got) != 1 || got[0].Name != "legacy, comma" {
		t.Fatal("new legacy report was split on comma")
	}
	got, err = Decode("default,office")
	if err != nil || len(got) != 2 {
		t.Fatal("existing CSV row rejected")
	}
	encoded, err = Encode(nats.Netbird{Profiles: []string{""}})
	if err != nil {
		t.Fatal(err)
	}
	got, err = Decode(encoded)
	if err != nil || len(got) != 0 {
		t.Fatal("legacy empty list was not normalized")
	}
}

func TestProfileStorageRejectsAmbiguityAndBounds(t *testing.T) {
	for _, profiles := range [][]nats.NetbirdProfile{
		{{Name: ""}}, {{Name: " bad"}}, {{Name: "bad\x00"}}, {{Name: strings.Repeat("x", MaxText+1)}}, {{Name: string([]byte{0xff})}}, {{ID: "../other", Name: "name"}}, {{ID: "same", Name: "first"}, {ID: "same", Name: "second"}}, {{Name: "same"}, {Name: "same"}}, {{Name: "first", Active: true}, {Name: "second", Active: true}}, make([]nats.NetbirdProfile, MaxProfiles+1),
	} {
		if _, err := Encode(nats.Netbird{ProfileDetails: profiles}); err == nil {
			t.Fatal("invalid profiles accepted")
		}
	}
	for _, raw := range []string{prefix + "null", prefix + "{}", prefix + `[{"name":""}]`, prefix + `[{"name":"a"},{"name":"a"}]`, "openuem-netbird-profiles:v2:[]", strings.Repeat("x", MaxStored+1), "a,,b"} {
		if _, err := Decode(raw); err == nil {
			t.Fatal("invalid stored profiles accepted")
		}
	}
}
