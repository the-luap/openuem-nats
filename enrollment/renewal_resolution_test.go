package enrollment

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nkeys"
)

func TestIdentityRenewalResolutionRequiresBothCandidateKeysAndExactIssuance(t *testing.T) {
	source, keys, other, now := renewalTestSource(t)
	target := RenewalConfirmationTarget{RequestID: uuid.NewString(), SourceCertificateHash: strings.Repeat("a", 64), Candidate: source}
	r, err := NewRenewalResolution(target, keys, now)
	if err != nil || ValidateRenewalResolution(*r, target, now) != nil {
		t.Fatal("valid candidate resolution rejected", err)
	}
	encoded, _ := json.Marshal(r)
	confirmation, err := NewRenewalConfirmation(target, keys, now)
	if err != nil {
		t.Fatal(err)
	}
	// Even normalized protocol fields cannot move a valid signature between
	// cancellation and activation; the signature domains remain separate.
	relabelled := RenewalConfirmation(*r)
	relabelled.Protocol = RenewalConfirmationProtocol
	if ValidateRenewalConfirmation(relabelled, target, now) == nil {
		t.Fatal("resolution proof authorized activation")
	}
	relabelledResolution := RenewalResolution(*confirmation)
	relabelledResolution.Protocol = RenewalResolutionProtocol
	if ValidateRenewalResolution(relabelledResolution, target, now) == nil {
		t.Fatal("activation proof cancelled issuance")
	}
	decoded, err := DecodeRenewalResolution(encoded)
	if err != nil || *decoded != *r {
		t.Fatal("resolution wire changed signed fields", err)
	}
	for _, incomplete := range []*Keys{nil, {}, other, {Certificate: &rsa.PrivateKey{}, Broker: keys.Broker}, {Certificate: keys.Certificate, Broker: other.Broker}, {Certificate: other.Certificate, Broker: keys.Broker}} {
		if got, err := NewRenewalResolution(target, incomplete, now); !errors.Is(err, ErrRenewalResolution) || got != nil {
			t.Fatal("resolution omitted a candidate key", err)
		}
	}
	for name, change := range map[string]func(*RenewalResolution){
		"protocol":              func(r *RenewalResolution) { r.Protocol = RenewalProtocol },
		"version":               func(r *RenewalResolution) { r.Version++ },
		"request":               func(r *RenewalResolution) { r.RequestID = uuid.NewString() },
		"device":                func(r *RenewalResolution) { r.DeviceID = uuid.NewString() },
		"organization":          func(r *RenewalResolution) { r.TenantID++ },
		"site":                  func(r *RenewalResolution) { r.SiteID++ },
		"origin":                func(r *RenewalResolution) { r.Origin = "https://other.example.test" },
		"platform":              func(r *RenewalResolution) { r.Platform = "macos" },
		"architecture":          func(r *RenewalResolution) { r.Architecture = "arm64" },
		"source certificate":    func(r *RenewalResolution) { r.SourceCertificateHash = strings.Repeat("b", 64) },
		"candidate certificate": func(r *RenewalResolution) { r.CertificateHash = strings.Repeat("b", 64) },
		"candidate broker":      func(r *RenewalResolution) { r.BrokerKey, _ = other.Broker.PublicKey() },
		"timestamp":             func(r *RenewalResolution) { r.IssuedAt++ },
		"certificate proof":     func(r *RenewalResolution) { r.CertificateProof = strings.Repeat("A", len(r.CertificateProof)) },
		"broker proof":          func(r *RenewalResolution) { r.BrokerProof = strings.Repeat("A", 86) },
		"noncanonical proof":    func(r *RenewalResolution) { r.BrokerProof += "=" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *r
			change(&changed)
			if err := ValidateRenewalResolution(changed, target, now); !errors.Is(err, ErrRenewalResolution) {
				t.Fatal("changed resolution accepted", err)
			}
		})
	}
	preparation, err := NewRenewalRequest(source, keys, keys, target.RequestID, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, signature := range []string{preparation.SourceBrokerProof, preparation.CandidateBrokerProof} {
		changed := *r
		changed.BrokerProof = signature
		if ValidateRenewalResolution(changed, target, now) == nil {
			t.Fatal("preparation broker proof activated issuance")
		}
	}
	changed := *r
	changed.CertificateProof = preparation.CertificateProof
	if ValidateRenewalResolution(changed, target, now) == nil {
		t.Fatal("preparation certificate proof activated issuance")
	}
	for _, at := range []time.Time{now.Add(RenewalProofLifetime + time.Second), now.Add(-RenewalClockSkew - time.Second), now.Add(25 * time.Hour)} {
		if ValidateRenewalResolution(*r, target, at) == nil {
			t.Fatal("expired certificate or stale/future resolution accepted")
		}
	}
	for _, at := range []time.Time{now.Add(RenewalProofLifetime), now.Add(-RenewalClockSkew)} {
		if err := ValidateRenewalResolution(*r, target, at); err != nil {
			t.Fatal("inclusive proof boundary rejected", err)
		}
	}
	for _, wire := range [][]byte{append(encoded, encoded...), []byte(strings.Replace(string(encoded), `"version":1`, `"version":1,"version":1`, 1)), []byte(strings.Replace(string(encoded), `"version":1`, `"Version":1`, 1)), []byte(strings.Replace(string(encoded), `"version":1`, `"version":null`, 1)), []byte(strings.Repeat(" ", MaxRenewalResolutionBytes+1)), append(encoded[:len(encoded)-1], []byte(`,"unknown":true}`)...)} {
		if _, err := DecodeRenewalResolution(wire); !errors.Is(err, ErrRenewalResolution) {
			t.Fatal("ambiguous resolution wire accepted", err)
		}
	}
}

func FuzzIdentityRenewalResolutionWire(f *testing.F) {
	key, err := nkeys.CreateUser()
	if err != nil {
		f.Fatal(err)
	}
	broker, _ := key.PublicKey()
	key.Wipe()
	r := RenewalResolution{Version: 1, Protocol: RenewalResolutionProtocol, RequestID: "11111111-1111-4111-8111-111111111111", DeviceID: "22222222-2222-4222-8222-222222222222", TenantID: 1, SiteID: 1, Origin: "https://uem.example.test", Platform: "windows", Architecture: "amd64", SourceCertificateHash: strings.Repeat("a", 64), CertificateHash: strings.Repeat("b", 64), BrokerKey: broker, IssuedAt: 1, CertificateProof: strings.Repeat("A", 512), BrokerProof: strings.Repeat("A", 86)}
	encoded, _ := json.Marshal(r)
	f.Add(encoded)
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := DecodeRenewalResolution(data)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(r)
		if err != nil || len(encoded) > MaxRenewalResolutionBytes {
			t.Fatal("decoded resolution exceeded its canonical wire bound")
		}
		again, err := DecodeRenewalResolution(encoded)
		if err != nil || *again != *r {
			t.Fatal("accepted resolution could not round trip", err)
		}
	})
}
