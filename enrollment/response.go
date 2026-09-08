package enrollment

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"time"
)

var ErrInvalidResponse = errors.New("individual enrollment response is invalid")

// Response contains public certificates and the identity selected by the server.
// The endpoint retains both private keys locally and verifies this certificate
// matches its key before installing the individual connection configuration.
type Response struct {
	Version     int       `json:"version"`
	DeviceID    string    `json:"device_id"`
	TenantID    int       `json:"tenant_id"`
	SiteID      int       `json:"site_id"`
	Endpoint    string    `json:"endpoint"`
	Certificate string    `json:"certificate"`
	Authority   string    `json:"authority"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// ValidateResponse binds the HTTPS-authenticated issuance result to the local
// CSR public key and the operator-authorized server origin. The supplied CA is
// an identity issuer, never a replacement for HTTPS server trust. Callers must
// authenticate the origin before accepting this response and persist pending
// endpoint keys before requesting issuance. No private key is needed here.
func ValidateResponse(response Response, expectedOrigin string, publicKey *rsa.PublicKey, now time.Time) (*x509.Certificate, error) {
	if !ValidOrigin(expectedOrigin) || response.Version != Version || !ValidDeviceID(response.DeviceID) || response.TenantID <= 0 || response.SiteID <= 0 || response.Endpoint != "wss"+strings.TrimPrefix(expectedOrigin, "https")+"/agent-channel" || publicKey == nil || publicKey.N == nil || publicKey.N.BitLen() < 3072 || publicKey.N.BitLen() > 4096 || publicKey.E != 65537 {
		return nil, ErrInvalidResponse
	}
	certificate, err := responseCertificate(response.Certificate, 16<<10)
	if err != nil {
		return nil, ErrInvalidResponse
	}
	authority, err := responseCertificate(response.Authority, 64<<10)
	if err != nil {
		return nil, ErrInvalidResponse
	}
	issuedKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || issuedKey.E != publicKey.E || issuedKey.N.Cmp(publicKey.N) != 0 || certificate.IsCA || !certificate.BasicConstraintsValid || certificate.Subject.CommonName != response.DeviceID || certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 || certificate.KeyUsage != x509.KeyUsageDigitalSignature || len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(certificate.UnknownExtKeyUsage) != 0 || len(certificate.DNSNames) != 0 || len(certificate.IPAddresses) != 0 || len(certificate.EmailAddresses) != 0 || len(certificate.URIs) != 1 || certificate.URIs[0].String() != "urn:openuem:agent:"+response.DeviceID {
		return nil, ErrInvalidResponse
	}
	if !validResponseAuthority(authority) || !certificate.NotAfter.Equal(response.ExpiresAt) || certificate.NotAfter.Sub(certificate.NotBefore) > 90*24*time.Hour+5*time.Minute {
		return nil, ErrInvalidResponse
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority)
	if _, err = certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, ErrInvalidResponse
	}
	return certificate, nil
}

func validResponseAuthority(certificate *x509.Certificate) bool {
	if !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 || certificate.SignatureAlgorithm == x509.MD5WithRSA || certificate.SignatureAlgorithm == x509.SHA1WithRSA || certificate.SignatureAlgorithm == x509.ECDSAWithSHA1 {
		return false
	}
	switch key := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen() >= 3072 && key.N.BitLen() <= 8192 && key.E == 65537
	case *ecdsa.PublicKey:
		return key.Curve == elliptic.P256() || key.Curve == elliptic.P384()
	case ed25519.PublicKey:
		return len(key) == ed25519.PublicKeySize
	default:
		return false
	}
}

// ValidOrigin requires an explicit HTTPS origin without credentials, path or
// query. It does not authorize an origin: that decision belongs to the operator
// or separately authenticated bootstrap configuration, never a server response.
func ValidOrigin(origin string) bool {
	if origin == "" || len(origin) > 2048 {
		return false
	}
	u, err := url.Parse(origin)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Path == "" && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && u.String() == origin
}

func responseCertificate(value string, limit int) (*x509.Certificate, error) {
	if len(value) == 0 || len(value) > limit || !strings.HasPrefix(value, "-----BEGIN CERTIFICATE-----") {
		return nil, ErrInvalidResponse
	}
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, ErrInvalidResponse
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrInvalidResponse
	}
	return certificate, nil
}
