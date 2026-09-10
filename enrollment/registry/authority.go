package registry

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Authority struct {
	TenantID     int       `json:"tenant_id"`
	Organization string    `json:"organization"`
	PublicOrigin string    `json:"public_origin"`
	Certificate  []byte    `json:"certificate"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func validOrigin(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Path == "" && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == ""
}

// EnsureAuthority creates one local CA or imports an existing enterprise signing
// CA. Repeated setup cannot silently rotate that key or redirect existing agents.
// Callers must require organization-wide certificate administration rights.
func (s *Store) EnsureAuthority(ctx context.Context, tenant int, organization, origin, actor string, certificatePEM, keyPEM []byte) (*Authority, error) {
	if tenant <= 0 || strings.TrimSpace(organization) == "" || len(organization) > 255 || strings.ContainsAny(organization, "\x00\r\n") || !validOrigin(origin) {
		return nil, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627911,$1::integer)`, tenant); err != nil {
		return nil, err
	}
	var authority Authority
	err = tx.QueryRowContext(ctx, `SELECT tenant_id,organization,public_origin,certificate,expires_at FROM uem_agent_authorities WHERE tenant_id=$1 FOR UPDATE`, tenant).Scan(&authority.TenantID, &authority.Organization, &authority.PublicOrigin, &authority.Certificate, &authority.ExpiresAt)
	if err == nil {
		if authority.Organization != organization || authority.PublicOrigin != origin || len(certificatePEM) != 0 || len(keyPEM) != 0 {
			return nil, ErrInvalid
		}
		return &authority, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if len(certificatePEM) == 0 && len(keyPEM) == 0 {
		certificatePEM, keyPEM, err = generateAuthority(organization)
		if err != nil {
			return nil, err
		}
	}
	ca, _, err := parseAuthority(certificatePEM, keyPEM)
	if err != nil {
		return nil, err
	}
	// Normalize to the one explicitly supplied signing CA. No arbitrary chain
	// or requested endpoint subject becomes an additional trust authority.
	certificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	encrypted, err := s.seal(keyPEM, fmt.Sprintf("%d/authority/key", tenant))
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_authorities(tenant_id,organization,public_origin,certificate,encrypted_key,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, tenant, organization, origin, certificatePEM, encrypted, ca.NotAfter)
	if err != nil {
		return nil, err
	}
	if err = audit(ctx, tx, Scope{TenantID: tenant}, actor, "agent.authority.create", uuid.NewString()); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &Authority{TenantID: tenant, Organization: organization, PublicOrigin: origin, Certificate: certificatePEM, ExpiresAt: ca.NotAfter}, nil
}

func generateAuthority(organization string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := certificateSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "OpenUEM individual agent CA", Organization: []string{organization}}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), nil
}

func certificateSerial() (*big.Int, error) {
	// Positive 159-bit serials fit RFC 5280's 20-octet bound without a sign byte.
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err == nil && n.Sign() == 0 {
		n.SetInt64(1)
	}
	return n, err
}

func parseAuthority(certificatePEM, keyPEM []byte) (*x509.Certificate, crypto.Signer, error) {
	if len(certificatePEM) > 64<<10 || len(keyPEM) > 32<<10 {
		return nil, nil, ErrInvalid
	}
	pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	ca, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 || ca.NotBefore.After(time.Now()) || !ca.NotAfter.After(time.Now().Add(24*time.Hour)) {
		return nil, nil, ErrInvalid
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, ErrInvalid
	}
	switch key := signer.Public().(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 3072 || key.N.BitLen() > 8192 || key.E != 65537 {
			return nil, nil, ErrInvalid
		}
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() && key.Curve != elliptic.P384() {
			return nil, nil, ErrInvalid
		}
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return nil, nil, ErrInvalid
		}
	default:
		return nil, nil, ErrInvalid
	}
	if ca.SignatureAlgorithm == x509.MD5WithRSA || ca.SignatureAlgorithm == x509.SHA1WithRSA || ca.SignatureAlgorithm == x509.ECDSAWithSHA1 {
		return nil, nil, ErrInvalid
	}
	return ca, signer, nil
}

func issueCertificate(ca *x509.Certificate, signer crypto.Signer, id string, public crypto.PublicKey) ([]byte, time.Time, error) {
	return issueCertificateAt(ca, signer, id, public, time.Now())
}

func issueCertificateAt(ca *x509.Certificate, signer crypto.Signer, id string, public crypto.PublicKey, now time.Time) ([]byte, time.Time, error) {
	serial, err := certificateSerial()
	if err != nil {
		return nil, time.Time{}, err
	}
	expires := now.Add(90 * 24 * time.Hour).Truncate(time.Second)
	if ca.NotAfter.Before(expires) {
		expires = ca.NotAfter
	}
	uri := &url.URL{Scheme: "urn", Opaque: "openuem:agent:" + id}
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: id}, URIs: []*url.URL{uri}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expires, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, ca, public, signer)
	if err != nil {
		return nil, time.Time{}, err
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err = issued.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, time.Time{}, err
	}
	return der, expires, err
}
