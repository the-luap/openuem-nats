package enrollment

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nkeys"
)

func renewalTestSource(t *testing.T) (RenewalSource, *Keys, *Keys, time.Time) {
	t.Helper()
	current, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Isolated renewal authority"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	id := uuid.NewString()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: id}, URIs: []*url.URL{{Scheme: "urn", Opaque: "openuem:agent:" + id}}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &current.Certificate.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	broker, _ := current.Broker.PublicKey()
	return RenewalSource{DeviceID: id, TenantID: 3, SiteID: 4, Origin: "https://uem.example.test", Platform: "windows", Architecture: "amd64", BrokerKey: broker, Certificate: der}, current, candidate, now
}

func TestIdentityRenewalProofBindsSourceAndCandidateKeys(t *testing.T) {
	source, current, candidate, now := renewalTestSource(t)
	id := uuid.NewString()
	request, err := NewRenewalRequest(source, current, candidate, id, now)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ValidateRenewalProof(*request, source, now)
	if err != nil || !proof.CertificateKey.Equal(&candidate.Certificate.PublicKey) || proof.BrokerKey != request.BrokerKey || len(proof.IntentDigest) != 64 {
		t.Fatal("renewal did not retain its proven target keys", err)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRenewalRequest(encoded)
	if err != nil || *decoded != *request {
		t.Fatal("renewal wire form changed intent", err)
	}
	if bytes.Contains(encoded, []byte("PRIVATE")) || bytes.Contains(encoded, []byte("seed")) {
		t.Fatal("renewal exposed private key material")
	}
	again, err := NewRenewalRequest(source, current, candidate, id, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	retry, err := ValidateRenewalProof(*again, source, now.Add(time.Minute))
	if err != nil || retry.IntentDigest != proof.IntentDigest || retry.KeyBinding != proof.KeyBinding || again.CertificateProof == request.CertificateProof {
		t.Fatal("fresh proof changed the pending renewal intent", err)
	}
	same, err := NewRenewalRequest(source, current, current, uuid.NewString(), now)
	if err != nil {
		t.Fatal("same-key certificate renewal rejected", err)
	}
	if _, err := ValidateRenewalProof(*same, source, now); err != nil {
		t.Fatal(err)
	}
	equivalent := *request
	alternateCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Ignored requested name"}}, candidate.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	equivalent.CSR = base64.StdEncoding.EncodeToString(alternateCSR)
	renewalTestSign(t, &equivalent, current, candidate)
	semantic, err := ValidateRenewalProof(equivalent, source, now)
	if err != nil || semantic.IntentDigest != proof.IntentDigest {
		t.Fatal("equivalent CSR changed persisted intent", err)
	}
	another, err := NewRenewalRequest(source, current, candidate, uuid.NewString(), now)
	if err != nil {
		t.Fatal(err)
	}
	distinct, err := ValidateRenewalProof(*another, source, now)
	if err != nil || distinct.IntentDigest == proof.IntentDigest {
		t.Fatal("different request reused pending intent", err)
	}
	// Existing enrollment and renewal must agree on the semantic key binding.
	enrollmentRequest, err := candidate.Request(testToken(t), source.Platform, source.Architecture, "Retained device")
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := Validate(*enrollmentRequest)
	if err != nil || enrolled.KeyBinding != proof.KeyBinding {
		t.Fatal("renewal changed shared key binding semantics", err)
	}
}

func TestIdentityRenewalRejectsTamperingAndProofRoleSubstitution(t *testing.T) {
	source, current, candidate, now := renewalTestSource(t)
	request, err := NewRenewalRequest(source, current, candidate, uuid.NewString(), now)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := nkeys.CreateUser()
	otherPublic, _ := other.PublicKey()
	for name, change := range map[string]func(*RenewalRequest){
		"protocol":           func(r *RenewalRequest) { r.Protocol = "filevault-rotation" },
		"version":            func(r *RenewalRequest) { r.Version++ },
		"request":            func(r *RenewalRequest) { r.RequestID = uuid.NewString() },
		"device":             func(r *RenewalRequest) { r.DeviceID = uuid.NewString() },
		"organization":       func(r *RenewalRequest) { r.TenantID++ },
		"site":               func(r *RenewalRequest) { r.SiteID++ },
		"origin":             func(r *RenewalRequest) { r.Origin = "https://other.example.test" },
		"platform":           func(r *RenewalRequest) { r.Platform = "macos" },
		"architecture":       func(r *RenewalRequest) { r.Architecture = "arm64" },
		"source certificate": func(r *RenewalRequest) { r.SourceCertificateHash = strings.Repeat("a", 64) },
		"source broker":      func(r *RenewalRequest) { r.SourceBrokerKey = otherPublic },
		"candidate broker":   func(r *RenewalRequest) { r.BrokerKey = otherPublic },
		"timestamp":          func(r *RenewalRequest) { r.IssuedAt++ },
		"certificate proof":  func(r *RenewalRequest) { r.CertificateProof = strings.Repeat("A", len(r.CertificateProof)) },
		"source proof":       func(r *RenewalRequest) { r.SourceBrokerProof = strings.Repeat("A", 86) },
		"candidate proof":    func(r *RenewalRequest) { r.CandidateBrokerProof = strings.Repeat("A", 86) },
		"proof roles": func(r *RenewalRequest) {
			r.SourceBrokerProof, r.CandidateBrokerProof = r.CandidateBrokerProof, r.SourceBrokerProof
		},
		"noncanonical CSR":       func(r *RenewalRequest) { r.CSR += "\n" },
		"oversized CSR":          func(r *RenewalRequest) { r.CSR = strings.Repeat("A", (12<<10)+1) },
		"noncanonical signature": func(r *RenewalRequest) { r.SourceBrokerProof += "=" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *request
			change(&changed)
			if p, err := ValidateRenewalProof(changed, source, now); !errors.Is(err, ErrRenewalProof) || p != nil {
				t.Fatal("tampered renewal accepted", err)
			}
		})
	}
	same, err := NewRenewalRequest(source, current, current, uuid.NewString(), now)
	if err != nil {
		t.Fatal(err)
	}
	same.SourceBrokerProof, same.CandidateBrokerProof = same.CandidateBrokerProof, same.SourceBrokerProof
	if _, err := ValidateRenewalProof(*same, source, now); !errors.Is(err, ErrRenewalProof) {
		t.Fatal("same-key proof roles could be interchanged", err)
	}
	for _, at := range []time.Time{now.Add(RenewalProofLifetime + time.Second), now.Add(-RenewalClockSkew - time.Second), now.Add(25 * time.Hour)} {
		if _, err := ValidateRenewalProof(*request, source, at); !errors.Is(err, ErrRenewalProof) {
			t.Fatal("stale or future renewal proof accepted", err)
		}
	}
}

func TestIdentityRenewalRequiresBothExistingPrivateKeys(t *testing.T) {
	source, current, candidate, now := renewalTestSource(t)
	for _, keys := range []*Keys{nil, {}, {Certificate: &rsa.PrivateKey{}, Broker: current.Broker}, candidate, {Certificate: current.Certificate, Broker: candidate.Broker}, {Certificate: candidate.Certificate, Broker: current.Broker}} {
		if r, err := NewRenewalRequest(source, keys, candidate, uuid.NewString(), now); !errors.Is(err, ErrRenewalProof) || r != nil {
			t.Fatal("renewal omitted existing private-key proof", err)
		}
	}
	request, err := NewRenewalRequest(source, current, candidate, uuid.NewString(), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*RenewalSource){func(s *RenewalSource) { s.TenantID++ }, func(s *RenewalSource) { s.SiteID++ }, func(s *RenewalSource) { s.Origin = "https://other.example.test" }, func(s *RenewalSource) { s.Certificate = append(bytes.Clone(s.Certificate), 0) }, func(s *RenewalSource) { s.DeviceID = uuid.NewString() }, func(s *RenewalSource) { s.BrokerKey, _ = candidate.Broker.PublicKey() }} {
		changed := source
		change(&changed)
		if p, err := ValidateRenewalProof(*request, changed, now); !errors.Is(err, ErrRenewalProof) || p != nil {
			t.Fatal("request overrode authoritative source", err)
		}
	}
	for _, at := range []time.Time{now.Add(25 * time.Hour), now.Add(-2 * time.Hour)} {
		if _, err := NewRenewalRequest(source, current, candidate, uuid.NewString(), at); !errors.Is(err, ErrRenewalProof) {
			t.Fatal("renewal used an expired or not-yet-valid source", err)
		}
	}
	weak, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRenewalRequest(source, current, &Keys{Certificate: weak, Broker: candidate.Broker}, uuid.NewString(), now); !errors.Is(err, ErrRenewalProof) {
		t.Fatal("weak candidate key accepted", err)
	}
}

func TestIdentityRenewalRejectsAmbiguousWireDocuments(t *testing.T) {
	source, current, candidate, now := renewalTestSource(t)
	r, err := NewRenewalRequest(source, current, candidate, uuid.NewString(), now)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(r)
	for _, data := range [][]byte{
		append([]byte(`{"version":1,`), encoded[1:]...),
		bytes.Replace(encoded, []byte(`"version"`), []byte(`"Version"`), 1),
		append([]byte(`{"extra":true,`), encoded[1:]...),
		append(bytes.Clone(encoded), []byte(` {}`)...),
		[]byte(`{"version":null}`),
		bytes.Repeat([]byte(" "), MaxRenewalRequestBytes+1),
	} {
		if got, err := DecodeRenewalRequest(data); !errors.Is(err, ErrRenewalProof) || got != nil {
			t.Fatal("ambiguous renewal wire document accepted", err)
		}
	}
	malformed := *r
	malformed.CSR = strings.Repeat("<", 12<<10)
	oversizedCanonical, _ := json.Marshal(malformed)
	if decoded, err := DecodeRenewalRequest(oversizedCanonical); !errors.Is(err, ErrRenewalProof) || decoded != nil {
		t.Fatal("non-base64 CSR escaped grammar bounds", err)
	}
	noncanonical, _ := json.Marshal(r)
	noncanonical = bytes.Replace(noncanonical, []byte(r.CSR), []byte("<"), 1)
	if decoded, err := DecodeRenewalRequest(noncanonical); !errors.Is(err, ErrRenewalProof) || decoded != nil {
		t.Fatal("raw non-base64 CSR accepted", err)
	}
	// A well-formed but damaged CSR is still rejected after decoding the wire.
	der, _ := base64.StdEncoding.DecodeString(r.CSR)
	der[len(der)-1] ^= 1
	r.CSR = base64.StdEncoding.EncodeToString(der)
	renewalTestSign(t, r, current, candidate)
	if _, err := ValidateRenewalProof(*r, source, now); !errors.Is(err, ErrRenewalProof) {
		t.Fatal("invalid candidate CSR signature accepted", err)
	}
}

func FuzzIdentityRenewalWire(f *testing.F) {
	broker, err := nkeys.FromRawSeed(nkeys.PrefixByteUser, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		f.Fatal(err)
	}
	public, err := broker.PublicKey()
	if err != nil {
		f.Fatal(err)
	}
	seed, err := json.Marshal(RenewalRequest{Version: RenewalVersion, Protocol: RenewalProtocol, RequestID: "dbeb3be8-803a-441d-809b-15003d5df08e", DeviceID: "86e1f43a-cb01-4aaf-867a-6428fae07a13", TenantID: 1, SiteID: 1, Origin: "https://uem.example.test", Platform: "windows", Architecture: "amd64", SourceCertificateHash: strings.Repeat("a", 64), SourceBrokerKey: public, IssuedAt: 1, CSR: "YQ==", BrokerKey: public, CertificateProof: strings.Repeat("A", 512), SourceBrokerProof: strings.Repeat("A", 86), CandidateBrokerProof: strings.Repeat("A", 86)})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"version":1,"protocol":"identity-renewal"}`))
	f.Add([]byte(`{"version":1,"version":1}`))
	f.Add([]byte(`{"csr":"%%%"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxRenewalRequestBytes+1 {
			return
		}
		r, err := DecodeRenewalRequest(data)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeRenewalRequest(encoded)
		if err != nil || *again != *r {
			t.Fatal("decoded renewal changed on canonical encoding", err)
		}
	})
}

func renewalTestSign(t *testing.T, r *RenewalRequest, current, candidate *Keys) {
	t.Helper()
	digest := sha256.Sum256(renewalMessage(*r, "source-certificate"))
	signature, err := rsa.SignPSS(rand.Reader, current.Certificate, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	r.CertificateProof = base64.RawURLEncoding.EncodeToString(signature)
	signature, err = current.Broker.Sign(renewalMessage(*r, "source-broker"))
	if err != nil {
		t.Fatal(err)
	}
	r.SourceBrokerProof = base64.RawURLEncoding.EncodeToString(signature)
	signature, err = candidate.Broker.Sign(renewalMessage(*r, "candidate-broker"))
	if err != nil {
		t.Fatal(err)
	}
	r.CandidateBrokerProof = base64.RawURLEncoding.EncodeToString(signature)
}
