package enrollment

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testRecoveryIdentity(t testing.TB) (RecoveryIdentity, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: id}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(der)
	return RecoveryIdentity{AgentID: id, TenantID: 1, SiteID: 2, CertificateHash: hex.EncodeToString(hash[:])}, cert, key
}

func testRecoveryContext(i RecoveryIdentity) RecoveryContext {
	return RecoveryContext{Version: RecoveryVersion, Identity: i, TaskID: uuid.NewString(), NativeID: uuid.NewString(), KeyID: uuid.NewString(), RecipientID: uuid.NewString(), ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}
}

func TestRecoveryHPKEBindsEveryRoutingFieldAndResult(t *testing.T) {
	i, cert, signer := testRecoveryIdentity(t)
	c := testRecoveryContext(i)
	key, err := NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	plain := []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")
	nonce := bytes.Repeat([]byte{7}, 32)
	recipient := RecoveryRecipient{ID: c.RecipientID, Identity: i, PublicKey: key.PublicKey()}
	task, err := EncryptRecoveryTask(recipient, c, plain, nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(task)
	if bytes.Contains(encoded, plain) || bytes.Contains(task.Ciphertext, plain) {
		t.Fatal("plaintext escaped HPKE")
	}
	secret, err := key.Open(*task, i, c.RecipientID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret.Key(), plain) {
		t.Fatal("wrong decrypted key")
	}
	if _, err = json.Marshal(secret); err == nil {
		t.Fatal("secret has a JSON representation")
	}
	if _, err = json.Marshal(key); err == nil {
		t.Fatal("recipient private key has a JSON representation")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", secret, secret), string(plain)) {
		t.Fatal("secret formatting exposed its contents")
	}
	result, err := secret.Result("invalid", cert, signer, time.Now())
	if err != nil || VerifyRecoveryResult(*result, cert, time.Now()) != nil {
		t.Fatal("valid signed result rejected", err)
	}
	result.Outcome = "valid"
	if VerifyRecoveryResult(*result, cert, time.Now()) == nil {
		t.Fatal("routing worker could change the validation outcome")
	}
	result.Outcome = "invalid"
	result.Context.KeyID = uuid.NewString()
	if VerifyRecoveryResult(*result, cert, time.Now()) == nil {
		t.Fatal("signature allowed another key version")
	}
	borrowed := secret.Key()
	secret.Close()
	if !bytes.Equal(borrowed, make([]byte, 29)) {
		t.Fatal("owned recovery bytes not cleared")
	}
	if _, err = secret.Result("valid", cert, signer, time.Now()); err == nil {
		t.Fatal("closed secret can sign a result")
	}
	for name, mutate := range map[string]func(*RecoveryTask){
		"task":          func(t *RecoveryTask) { t.Context.TaskID = uuid.NewString() },
		"native":        func(t *RecoveryTask) { t.Context.NativeID = uuid.NewString() },
		"key":           func(t *RecoveryTask) { t.Context.KeyID = uuid.NewString() },
		"scope":         func(t *RecoveryTask) { t.Context.Identity.SiteID++ },
		"agent":         func(t *RecoveryTask) { t.Context.Identity.AgentID = uuid.NewString() },
		"certificate":   func(t *RecoveryTask) { t.Context.Identity.CertificateHash = strings.Repeat("f", 64) },
		"recipient":     func(t *RecoveryTask) { t.Context.RecipientID = uuid.NewString() },
		"expiry":        func(t *RecoveryTask) { t.Context.ExpiresAt++ },
		"ciphertext":    func(t *RecoveryTask) { t.Ciphertext = bytes.Clone(t.Ciphertext); t.Ciphertext[0] ^= 1 },
		"encapsulation": func(t *RecoveryTask) { t.Encapsulation = bytes.Clone(t.Encapsulation); t.Encapsulation[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *task
			mutate(&changed)
			if opened, err := key.Open(changed, changed.Context.Identity, changed.Context.RecipientID, time.Now()); !errors.Is(err, ErrRecovery) || opened != nil {
				t.Fatal("mutated HPKE context accepted")
			}
		})
	}
	other, err := NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if opened, err := other.Open(*task, i, c.RecipientID, time.Now()); !errors.Is(err, ErrRecovery) || opened != nil {
		t.Fatal("wrong recipient accepted")
	}
	serialized, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(serialized)
	loaded, err := ParseRecoveryRecipientKey(serialized)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if !bytes.Equal(loaded.PublicKey(), key.PublicKey()) {
		t.Fatal("protected recipient round trip changed identity")
	}
}

func TestRecoveryRegistrationRequiresExactSigningIdentity(t *testing.T) {
	i, cert, key := testRecoveryIdentity(t)
	recipient, err := NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer recipient.Close()
	c := RecoveryRegistration{Version: 1, Identity: i, ID: uuid.NewString(), PublicKey: recipient.PublicKey(), Nonce: bytes.Repeat([]byte{9}, 32), ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}
	signature, err := SignRecoveryRegistration(c, cert, key, time.Now())
	if err != nil || VerifyRecoveryRegistration(c, signature, cert, time.Now()) != nil {
		t.Fatal("registration signature rejected", err)
	}
	for _, mutate := range []func(*RecoveryRegistration){
		func(c *RecoveryRegistration) { c.Identity.SiteID++ }, func(c *RecoveryRegistration) { c.Identity.AgentID = uuid.NewString() },
		func(c *RecoveryRegistration) { c.ID = uuid.NewString() }, func(c *RecoveryRegistration) { c.ExpiresAt++ },
		func(c *RecoveryRegistration) { c.PublicKey = bytes.Clone(c.PublicKey); c.PublicKey[0] ^= 1 },
		func(c *RecoveryRegistration) { c.Nonce = bytes.Clone(c.Nonce); c.Nonce[0] ^= 1 },
	} {
		changed := c
		mutate(&changed)
		if VerifyRecoveryRegistration(changed, signature, cert, time.Now()) == nil {
			t.Fatal("changed registration accepted")
		}
	}
	if VerifyRecoveryRegistration(c, signature, cert, time.Now().Add(6*time.Minute)) == nil {
		t.Fatal("expired registration accepted")
	}
	wrong := *cert
	wrong.KeyUsage = x509.KeyUsageKeyEncipherment
	if _, err = SignRecoveryRegistration(c, &wrong, key, time.Now()); err == nil {
		t.Fatal("encryption-only certificate signed registration")
	}
	if ValidRecoveryPublicKey(make([]byte, 32)) {
		t.Fatal("low-order X25519 recipient accepted")
	}
}

func TestRecoveryWireRejectsAmbiguousOrOversizedRequests(t *testing.T) {
	key, err := NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	r := RecoveryRequest{Version: 1, AgentID: uuid.NewString(), Action: "challenge", PublicKey: key.PublicKey()}
	valid, _ := json.Marshal(r)
	if _, err = DecodeRecoveryRequest(valid, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{
		append(bytes.Clone(valid), []byte("{}")...), bytes.Repeat([]byte("x"), MaxRecoveryMessage+1),
		bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"Version":1`), 1),
		bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"extra":true`), 1),
		bytes.Replace(valid, []byte(`"action":"challenge"`), []byte(`"action":"poll"`), 1),
	} {
		if _, err = DecodeRecoveryRequest(data, time.Now()); !errors.Is(err, ErrRecovery) {
			t.Fatal("ambiguous recovery request accepted")
		}
	}
}

func FuzzRecoveryRequestBoundaries(f *testing.F) {
	f.Add([]byte(`{"version":1,"agent_id":"11111111-2222-3333-4444-555555555555","action":"poll","recipient_id":"11111111-2222-3333-4444-555555555556"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := DecodeRecoveryRequest(data, time.Unix(1800000000, 0))
		if err != nil && !errors.Is(err, ErrRecovery) {
			t.Fatal("unexpected error class")
		}
		if r != nil {
			encoded, _ := json.Marshal(r)
			if !bytes.Equal(encoded, data) {
				t.Fatal("accepted noncanonical wire data")
			}
		}
	})
}
