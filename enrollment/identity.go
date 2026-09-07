// Package enrollment defines the versioned individual-agent enrollment proof.
// Private keys are generated on the endpoint and never included in requests.
package enrollment

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/nats-io/nkeys"
)

const Version = 1

var ErrInvalidProof = errors.New("invalid individual-agent enrollment proof")

type Request struct {
	Version      int    `json:"version"`
	Invitation   string `json:"invitation"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	DeviceName   string `json:"device_name"`
	CSR          string `json:"csr"`
	BrokerKey    string `json:"broker_key"`
	Proof        string `json:"proof"`
}

type PublicIdentity struct {
	CertificateKey *rsa.PublicKey
	BrokerKey      string
	KeyBinding     string
}

// Keys must be protected by the endpoint's local key storage. There is no JSON
// representation or server-side private-key generation in this protocol.
type Keys struct {
	Certificate *rsa.PrivateKey `json:"-"`
	Broker      nkeys.KeyPair   `json:"-"`
}

func (k Keys) MarshalJSON() ([]byte, error) {
	return nil, errors.New("private enrollment keys cannot be serialized as JSON")
}

func GenerateKeys() (*Keys, error) {
	certificate, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	broker, err := nkeys.CreateUser()
	if err != nil {
		return nil, err
	}
	return &Keys{Certificate: certificate, Broker: broker}, nil
}

func ValidToken(token string) bool {
	data, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(data) == 32 && base64.RawURLEncoding.EncodeToString(data) == token
}

func validTarget(platform, architecture string) bool {
	return (platform == "windows" || platform == "macos") && (architecture == "amd64" || architecture == "arm64")
}

func (k *Keys) Request(invitation, platform, architecture, deviceName string) (*Request, error) {
	if k == nil || k.Certificate == nil || k.Broker == nil {
		return nil, ErrInvalidProof
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "OpenUEM agent enrollment"}}, k.Certificate)
	if err != nil {
		return nil, err
	}
	publicKey, err := k.Broker.PublicKey()
	if err != nil {
		return nil, err
	}
	r := &Request{Version: Version, Invitation: invitation, Platform: platform, Architecture: architecture, DeviceName: deviceName, CSR: base64.StdEncoding.EncodeToString(csr), BrokerKey: publicKey}
	message, err := proofMessage(*r)
	if err != nil {
		return nil, err
	}
	signature, err := k.Broker.Sign(message)
	if err != nil {
		return nil, err
	}
	r.Proof = base64.RawURLEncoding.EncodeToString(signature)
	if _, err = Validate(*r); err != nil {
		return nil, err
	}
	return r, nil
}

func proofMessage(request Request) ([]byte, error) {
	request.Proof = ""
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	return append([]byte("openuem/agent/enrollment/v1\x00"), hash[:]...), nil
}

func Validate(request Request) (*PublicIdentity, error) {
	if request.Version != Version || !ValidToken(request.Invitation) || !validTarget(request.Platform, request.Architecture) || len(request.DeviceName) > 255 || strings.ContainsAny(request.DeviceName, "\x00\r\n") || len(request.CSR) > 12<<10 || !nkeys.IsValidPublicUserKey(request.BrokerKey) || len(request.Proof) != 86 {
		return nil, ErrInvalidProof
	}
	der, err := base64.StdEncoding.Strict().DecodeString(request.CSR)
	if err != nil || base64.StdEncoding.EncodeToString(der) != request.CSR {
		return nil, ErrInvalidProof
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, ErrInvalidProof
	}
	key, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 3072 || key.N.BitLen() > 4096 || key.E != 65537 {
		return nil, ErrInvalidProof
	}
	if csr.SignatureAlgorithm != x509.SHA256WithRSA || csr.CheckSignature() != nil {
		return nil, ErrInvalidProof
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(request.Proof)
	if err != nil || len(signature) != 64 {
		return nil, ErrInvalidProof
	}
	publicKey, err := nkeys.FromPublicKey(request.BrokerKey)
	if err != nil {
		return nil, ErrInvalidProof
	}
	message, err := proofMessage(request)
	if err != nil || publicKey.Verify(message, signature) != nil {
		return nil, ErrInvalidProof
	}
	// Bind retries to the keys, not the CSR's random signature or requested
	// subject. The issuer must construct the certificate identity itself.
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, ErrInvalidProof
	}
	binding := sha256.Sum256(append(append([]byte("openuem/agent/key-binding/v1\x00"), encoded...), []byte("\x00"+request.BrokerKey)...))
	return &PublicIdentity{CertificateKey: key, BrokerKey: request.BrokerKey, KeyBinding: hex.EncodeToString(binding[:])}, nil
}
