package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func TestOriginKeysBindExactAuthorizedOriginAndOwnReturnedBuffers(t *testing.T) {
	origin := "https://uem.example.test"
	var keys []ed25519.PublicKey
	for range 8 {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		clear(private)
		keys = append(keys, public)
	}
	data, err := MarshalOriginKeys(origin, keys)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseOriginKeys(data, origin)
	if err != nil || len(parsed) != 8 {
		t.Fatal("could not parse the authenticated ring", err)
	}
	for i := range keys {
		if !bytes.Equal(keys[i], parsed[i]) {
			t.Fatal("origin key changed")
		}
	}
	clear(parsed[0])
	again, err := ParseOriginKeys(data, origin)
	if err != nil || !bytes.Equal(again[0], keys[0]) {
		t.Fatal("returned keys alias the document or source")
	}
	for _, wrong := range []string{"https://other.example.test", origin + "/", "http://uem.example.test", "https://uem.example.test:443"} {
		if _, err := ParseOriginKeys(data, wrong); err == nil {
			t.Fatal("accepted changed origin")
		}
	}
	for _, invalid := range [][]ed25519.PublicKey{nil, {{}}, {keys[0], keys[0]}, append(keys, keys[0])} {
		if _, err := MarshalOriginKeys(origin, invalid); err == nil {
			t.Fatal("published an invalid key ring")
		}
	}
}

func TestOriginKeysRejectAmbiguousUnboundedAndMalformedDocuments(t *testing.T) {
	f := newFixture(t)
	valid, err := MarshalOriginKeys(f.config.Origin, f.trust.BootstrapKeys)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"empty":        func([]byte) []byte { return nil },
		"too large":    func(b []byte) []byte { return append(b, bytes.Repeat([]byte(" "), MaxOriginKeysSize)...) },
		"duplicate":    func(b []byte) []byte { return append([]byte(`{"schema":1,`), b[1:]...) },
		"case alias":   func(b []byte) []byte { return bytes.Replace(b, []byte(`"schema"`), []byte(`"Schema"`), 1) },
		"unknown":      func(b []byte) []byte { return append([]byte(`{"untrusted":true,`), b[1:]...) },
		"trailing":     func(b []byte) []byte { return append(b, []byte(`{}`)...) },
		"invalid UTF8": func(b []byte) []byte { return append(b, 0xff) },
		"null":         func([]byte) []byte { return []byte(`null`) },
		"wrong schema": func(b []byte) []byte { return bytes.Replace(b, []byte(`"schema":1`), []byte(`"schema":2`), 1) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseOriginKeys(mutate(bytes.Clone(valid)), f.config.Origin); err == nil {
				t.Fatal("accepted unsafe document")
			}
		})
	}
	for name, mutate := range map[string]func(*originKeys){
		"missing ring":  func(d *originKeys) { d.Keys = nil },
		"empty ring":    func(d *originKeys) { d.Keys = []originKey{} },
		"duplicate key": func(d *originKeys) { d.Keys = append(d.Keys, d.Keys[0]) },
		"large ring": func(d *originKeys) {
			for len(d.Keys) < 9 {
				d.Keys = append(d.Keys, d.Keys[0])
			}
		},
		"wrong fingerprint":     func(d *originKeys) { d.Keys[0].KeyID = strings.Repeat("0", 64) },
		"uppercase fingerprint": func(d *originKeys) { d.Keys[0].KeyID = strings.ToUpper(d.Keys[0].KeyID) },
		"padded key":            func(d *originKeys) { d.Keys[0].PublicKey += "=" },
		"base64 newline":        func(d *originKeys) { d.Keys[0].PublicKey += "\n" },
		"short key":             func(d *originKeys) { d.Keys[0].PublicKey = "YQ" },
		"null key fields":       func(d *originKeys) { d.Keys[0] = originKey{} },
	} {
		t.Run(name, func(t *testing.T) {
			var d originKeys
			if err := json.Unmarshal(valid, &d); err != nil {
				t.Fatal(err)
			}
			mutate(&d)
			data, _ := json.Marshal(d)
			if _, err := ParseOriginKeys(data, f.config.Origin); err == nil {
				t.Fatal("accepted malformed key ring")
			}
		})
	}
}
