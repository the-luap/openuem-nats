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

func TestIdentityRenewalConfirmationRequiresBothCandidateKeysAndExactIssuance(t *testing.T) {
	source, keys, other, now := renewalTestSource(t)
	target := RenewalConfirmationTarget{RequestID: uuid.NewString(), SourceCertificateHash: strings.Repeat("a", 64), Candidate: source}
	r, err := NewRenewalConfirmation(target, keys, now)
	if err != nil || ValidateRenewalConfirmation(*r, target, now) != nil {
		t.Fatal("valid candidate confirmation rejected", err)
	}
	encoded, _ := json.Marshal(r)
	decoded, err := DecodeRenewalConfirmation(encoded)
	if err != nil || *decoded != *r {
		t.Fatal("confirmation wire changed signed fields", err)
	}
	for _, incomplete := range []*Keys{nil, {}, other, {Certificate: &rsa.PrivateKey{}, Broker: keys.Broker}, {Certificate: keys.Certificate, Broker: other.Broker}, {Certificate: other.Certificate, Broker: keys.Broker}} {
		if got, err := NewRenewalConfirmation(target, incomplete, now); !errors.Is(err, ErrRenewalConfirmation) || got != nil {
			t.Fatal("confirmation omitted a candidate key", err)
		}
	}
	for name, change := range map[string]func(*RenewalConfirmation){
		"protocol":              func(r *RenewalConfirmation) { r.Protocol = RenewalProtocol },
		"version":               func(r *RenewalConfirmation) { r.Version++ },
		"request":               func(r *RenewalConfirmation) { r.RequestID = uuid.NewString() },
		"device":                func(r *RenewalConfirmation) { r.DeviceID = uuid.NewString() },
		"organization":          func(r *RenewalConfirmation) { r.TenantID++ },
		"site":                  func(r *RenewalConfirmation) { r.SiteID++ },
		"origin":                func(r *RenewalConfirmation) { r.Origin = "https://other.example.test" },
		"platform":              func(r *RenewalConfirmation) { r.Platform = "macos" },
		"architecture":          func(r *RenewalConfirmation) { r.Architecture = "arm64" },
		"source certificate":    func(r *RenewalConfirmation) { r.SourceCertificateHash = strings.Repeat("b", 64) },
		"candidate certificate": func(r *RenewalConfirmation) { r.CertificateHash = strings.Repeat("b", 64) },
		"candidate broker":      func(r *RenewalConfirmation) { r.BrokerKey, _ = other.Broker.PublicKey() },
		"timestamp":             func(r *RenewalConfirmation) { r.IssuedAt++ },
		"certificate proof":     func(r *RenewalConfirmation) { r.CertificateProof = strings.Repeat("A", len(r.CertificateProof)) },
		"broker proof":          func(r *RenewalConfirmation) { r.BrokerProof = strings.Repeat("A", 86) },
		"noncanonical proof":    func(r *RenewalConfirmation) { r.BrokerProof += "=" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *r
			change(&changed)
			if err := ValidateRenewalConfirmation(changed, target, now); !errors.Is(err, ErrRenewalConfirmation) {
				t.Fatal("changed confirmation accepted", err)
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
		if ValidateRenewalConfirmation(changed, target, now) == nil {
			t.Fatal("preparation broker proof activated issuance")
		}
	}
	changed := *r
	changed.CertificateProof = preparation.CertificateProof
	if ValidateRenewalConfirmation(changed, target, now) == nil {
		t.Fatal("preparation certificate proof activated issuance")
	}
	for _, at := range []time.Time{now.Add(RenewalProofLifetime + time.Second), now.Add(-RenewalClockSkew - time.Second), now.Add(25 * time.Hour)} {
		if ValidateRenewalConfirmation(*r, target, at) == nil {
			t.Fatal("expired certificate or stale/future confirmation accepted")
		}
	}
	for _, at := range []time.Time{now.Add(RenewalProofLifetime), now.Add(-RenewalClockSkew)} {
		if err := ValidateRenewalConfirmation(*r, target, at); err != nil {
			t.Fatal("inclusive proof boundary rejected", err)
		}
	}
	for _, wire := range [][]byte{append(encoded, encoded...), []byte(strings.Replace(string(encoded), `"version":1`, `"version":1,"version":1`, 1)), []byte(strings.Replace(string(encoded), `"version":1`, `"Version":1`, 1)), []byte(strings.Replace(string(encoded), `"version":1`, `"version":null`, 1)), []byte(strings.Repeat(" ", MaxRenewalConfirmationBytes+1)), append(encoded[:len(encoded)-1], []byte(`,"unknown":true}`)...)} {
		if _, err := DecodeRenewalConfirmation(wire); !errors.Is(err, ErrRenewalConfirmation) {
			t.Fatal("ambiguous confirmation wire accepted", err)
		}
	}
}

func FuzzIdentityRenewalConfirmationWire(f *testing.F) {
	key, err := nkeys.CreateUser()
	if err != nil {
		f.Fatal(err)
	}
	broker, _ := key.PublicKey()
	key.Wipe()
	r := RenewalConfirmation{Version: 1, Protocol: RenewalConfirmationProtocol, RequestID: "11111111-1111-4111-8111-111111111111", DeviceID: "22222222-2222-4222-8222-222222222222", TenantID: 1, SiteID: 1, Origin: "https://uem.example.test", Platform: "windows", Architecture: "amd64", SourceCertificateHash: strings.Repeat("a", 64), CertificateHash: strings.Repeat("b", 64), BrokerKey: broker, IssuedAt: 1, CertificateProof: strings.Repeat("A", 512), BrokerProof: strings.Repeat("A", 86)}
	encoded, _ := json.Marshal(r)
	f.Add(encoded)
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := DecodeRenewalConfirmation(data)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(r)
		if err != nil || len(encoded) > MaxRenewalConfirmationBytes {
			t.Fatal("decoded confirmation exceeded its canonical wire bound")
		}
		again, err := DecodeRenewalConfirmation(encoded)
		if err != nil || *again != *r {
			t.Fatal("accepted confirmation could not round trip", err)
		}
	})
}
