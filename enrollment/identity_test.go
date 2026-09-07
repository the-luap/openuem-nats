package enrollment

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
)

func testToken(t *testing.T) string {
	t.Helper()
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func TestEnrollmentProofBindsBothKeysInvitationAndTarget(t *testing.T) {
	keys, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	request, err := keys.Request(testToken(t), "windows", "amd64", "Workstation")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := Validate(*request)
	if err != nil {
		t.Fatal(err)
	}
	if identity.CertificateKey.N.Cmp(keys.Certificate.N) != 0 || len(identity.KeyBinding) != 64 {
		t.Fatal("proof returned another public identity")
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "PRIVATE") || strings.Contains(string(encoded), "seed") {
		t.Fatal("request contains private key fields")
	}
	if _, err = json.Marshal(keys); err == nil {
		t.Fatal("private enrollment keys were serializable in a JSON request")
	}
	other, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, _ := other.PublicKey()
	for name, change := range map[string]func(*Request){
		"invitation":   func(r *Request) { r.Invitation = testToken(t) },
		"platform":     func(r *Request) { r.Platform = "macos" },
		"architecture": func(r *Request) { r.Architecture = "arm64" },
		"name":         func(r *Request) { r.DeviceName = "Other" },
		"broker key":   func(r *Request) { r.BrokerKey = otherPublic },
		"version":      func(r *Request) { r.Version++ },
		"CSR":          func(r *Request) { r.CSR = strings.Repeat("A", 20<<10) },
		"signature":    func(r *Request) { r.Proof = strings.Repeat("A", 86) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *request
			change(&changed)
			if _, err := Validate(changed); !errors.Is(err, ErrInvalidProof) {
				t.Fatal("tampered proof accepted", err)
			}
		})
	}
	// A new CSR made with the same endpoint keys still identifies the same
	// enrollment, so a retried request can recover only that endpoint's result.
	again, err := keys.Request(request.Invitation, request.Platform, request.Architecture, request.DeviceName)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Validate(*again)
	if err != nil || second.KeyBinding != identity.KeyBinding {
		t.Fatal("retry changed identity binding", err)
	}
}

func TestEnrollmentRejectsWeakOrInvalidCSRAndUnsupportedDevices(t *testing.T) {
	keys, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range [][2]string{{"linux", "amd64"}, {"windows", "386"}, {"macos", ""}} {
		if _, err = keys.Request(testToken(t), target[0], target[1], "Device"); !errors.Is(err, ErrInvalidProof) {
			t.Fatal("unsupported target accepted", target, err)
		}
	}
	weak, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys.Certificate = weak
	if _, err = keys.Request(testToken(t), "windows", "amd64", "Device"); !errors.Is(err, ErrInvalidProof) {
		t.Fatal("weak key accepted", err)
	}
	keys, err = GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	request, err := keys.Request(testToken(t), "macos", "arm64", "Mac")
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Another CSR"}}, keys.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	der[len(der)-1] ^= 1
	request.CSR = base64.StdEncoding.EncodeToString(der)
	message, _ := proofMessage(*request)
	proof, _ := keys.Broker.Sign(message)
	request.Proof = base64.RawURLEncoding.EncodeToString(proof)
	if _, err = Validate(*request); !errors.Is(err, ErrInvalidProof) {
		t.Fatal("invalid CSR signature accepted with valid broker proof", err)
	}
}
