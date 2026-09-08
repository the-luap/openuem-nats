package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

type responseFixture struct {
	keys      *Keys
	authority *x509.Certificate
	signer    *ecdsa.PrivateKey
	leaf      *x509.Certificate
	response  Response
}

func newResponseFixture(t *testing.T) *responseFixture {
	t.Helper()
	keys, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Broker.Wipe)
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Isolated identity authority"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &signer.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	id := "6f73f916-8aaf-4cd1-92e9-c8cbb11028ba"
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: id}, URIs: []*url.URL{{Scheme: "urn", Opaque: "openuem:agent:" + id}}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	f := &responseFixture{keys: keys, authority: ca, signer: signer, leaf: leaf}
	f.response = Response{Version: Version, DeviceID: id, TenantID: 1, SiteID: 2, Endpoint: "wss://uem.example.test/agent-channel", Certificate: f.sign(t, *leaf), Authority: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), ExpiresAt: leaf.NotAfter}
	return f
}

func (f *responseFixture) sign(t *testing.T, template x509.Certificate) string {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, &template, f.authority, &f.keys.Certificate.PublicKey, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestIssuedResponseBindsLocalKeyIdentityOriginAndCertificatePurpose(t *testing.T) {
	f := newResponseFixture(t)
	if _, err := ValidateResponse(f.response, "https://uem.example.test", &f.keys.Certificate.PublicKey, time.Now()); err != nil {
		t.Fatal("valid issued response rejected", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Response)
	}{
		{"wrong schema", func(r *Response) { r.Version++ }},
		{"empty tenant", func(r *Response) { r.TenantID = 0 }},
		{"negative site", func(r *Response) { r.SiteID = -1 }},
		{"uppercase identity", func(r *Response) { r.DeviceID = strings.ToUpper(r.DeviceID) }},
		{"different identity", func(r *Response) { r.DeviceID = "bf1feccc-fad8-47b4-9d8d-3479b02dd881" }},
		{"other WSS origin", func(r *Response) { r.Endpoint = "wss://other.example.test/agent-channel" }},
		{"other WSS path", func(r *Response) { r.Endpoint = "wss://uem.example.test/admin" }},
		{"WSS query credential", func(r *Response) { r.Endpoint += "?token=private" }},
		{"unbound expiry", func(r *Response) { r.ExpiresAt = r.ExpiresAt.Add(time.Second) }},
		{"extra certificate", func(r *Response) { r.Certificate += r.Certificate }},
		{"prefixed certificate garbage", func(r *Response) { r.Certificate = "ignored garbage\n" + r.Certificate }},
		{"oversized certificate", func(r *Response) { r.Certificate = strings.Repeat("x", (16<<10)+1) }},
		{"leaf used as authority", func(r *Response) { r.Authority = r.Certificate }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := f.response
			tc.change(&r)
			if _, err := ValidateResponse(r, "https://uem.example.test", &f.keys.Certificate.PublicKey, time.Now()); !errors.Is(err, ErrInvalidResponse) {
				t.Fatal("unbound response accepted", err)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*x509.Certificate)
	}{
		{"authority privilege", func(c *x509.Certificate) { c.IsCA = true }},
		{"server authentication", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }},
		{"extra authentication role", func(c *x509.Certificate) {
			c.ExtKeyUsage = append([]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, x509.ExtKeyUsageServerAuth)
		}},
		{"signing privilege", func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCertSign }},
		{"wrong subject", func(c *x509.Certificate) { c.Subject.CommonName = "other endpoint" }},
		{"missing identity URI", func(c *x509.Certificate) { c.URIs = nil }},
		{"extra URI", func(c *x509.Certificate) {
			c.URIs = append(append([]*url.URL(nil), c.URIs...), &url.URL{Scheme: "urn", Opaque: "unrelated"})
		}},
		{"extra DNS identity", func(c *x509.Certificate) { c.DNSNames = []string{"unexpected.example.test"} }},
		{"extra email identity", func(c *x509.Certificate) { c.EmailAddresses = []string{"unexpected@example.test"} }},
		{"expired", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }},
		{"not yet valid", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }},
		{"excessive lifetime", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(-91 * 24 * time.Hour) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := *f.leaf
			tc.change(&c)
			r := f.response
			r.Certificate = f.sign(t, c)
			r.ExpiresAt = c.NotAfter
			if _, err := ValidateResponse(r, "https://uem.example.test", &f.keys.Certificate.PublicKey, time.Now()); !errors.Is(err, ErrInvalidResponse) {
				t.Fatal("overprivileged or unbound certificate accepted", err)
			}
		})
	}
	other := newResponseFixture(t)
	if _, err := ValidateResponse(f.response, "https://uem.example.test", &other.keys.Certificate.PublicKey, time.Now()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("certificate for another local key accepted")
	}
	r := f.response
	r.Authority = other.response.Authority
	if _, err := ValidateResponse(r, "https://uem.example.test", &f.keys.Certificate.PublicKey, time.Now()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("wrong issuing authority accepted")
	}
}

func TestEnrollmentOriginRequiresAnExplicitCredentialFreeHTTPSOrigin(t *testing.T) {
	for _, origin := range []string{"https://uem.example.test", "https://uem.example.test:8443", "https://[2001:db8::1]"} {
		if !ValidOrigin(origin) {
			t.Fatal("valid origin rejected")
		}
	}
	for _, origin := range []string{"", "http://uem.example.test", "https://user:secret@uem.example.test", "https://uem.example.test/", "https://uem.example.test/agent-channel", "https://uem.example.test?", "https://uem.example.test?token=private", "https://uem.example.test#fragment", "https://uem.example.test#", "//uem.example.test"} {
		if ValidOrigin(origin) {
			t.Fatal("ambiguous enrollment origin accepted")
		}
	}
}

func TestIssuedResponseRejectsAWeakIdentityAuthority(t *testing.T) {
	f := newResponseFixture(t)
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ca := *f.authority
	ca.SignatureAlgorithm = x509.SHA256WithRSA
	ca.PublicKey, ca.PublicKeyAlgorithm, ca.SubjectKeyId = &weak.PublicKey, x509.RSA, nil
	der, err := x509.CreateCertificate(rand.Reader, &ca, &ca, &weak.PublicKey, weak)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.CreateCertificate(rand.Reader, f.leaf, authority, &f.keys.Certificate.PublicKey, weak)
	if err != nil {
		t.Fatal(err)
	}
	r := f.response
	r.Authority = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	r.Certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}))
	if _, err = ValidateResponse(r, "https://uem.example.test", &f.keys.Certificate.PublicKey, time.Now()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("weak signing authority accepted", err)
	}
}
