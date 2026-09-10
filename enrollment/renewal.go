package enrollment

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment/internal/strictjson"
)

const RenewalVersion = 1
const RenewalProtocol = "identity-renewal"
const MaxRenewalRequestBytes = 32 << 10
const RenewalProofLifetime = 15 * time.Minute
const RenewalClockSkew = time.Minute

var ErrRenewalProof = errors.New("invalid individual-agent identity renewal proof")

// RenewalSource is authoritative, currently authorized registry state, never
// source information copied from the request. The service must hold its identity
// and scope locks while validating this proof and persisting issuance/retry state.
// Certificate is the exact existing DER certificate whose possession is proven.
type RenewalSource struct {
	DeviceID, Origin, Platform, Architecture, BrokerKey string
	TenantID, SiteID                                    int
	Certificate                                         []byte
}

// RenewalRequest binds both existing private keys to the candidate CSR/key and
// proves possession of the candidate broker key independently. No private key is
// sent. Proof freshness is not replay prevention: services must persist RequestID
// and IntentDigest, serialize issuance, and confirm replacement use separately.
type RenewalRequest struct {
	Version               int    `json:"version"`
	Protocol              string `json:"protocol"`
	RequestID             string `json:"request_id"`
	DeviceID              string `json:"device_id"`
	TenantID              int    `json:"tenant_id"`
	SiteID                int    `json:"site_id"`
	Origin                string `json:"origin"`
	Platform              string `json:"platform"`
	Architecture          string `json:"architecture"`
	SourceCertificateHash string `json:"source_certificate_hash"`
	SourceBrokerKey       string `json:"source_broker_key"`
	IssuedAt              int64  `json:"issued_at"`
	CSR                   string `json:"csr"`
	BrokerKey             string `json:"broker_key"`
	CertificateProof      string `json:"certificate_proof"`
	SourceBrokerProof     string `json:"source_broker_proof"`
	CandidateBrokerProof  string `json:"candidate_broker_proof"`
}

type RenewalProof struct {
	PublicIdentity
	// IntentDigest is stable across fresh signatures/timestamps and equivalent
	// CSRs for the same keys. A service may retry only this same persisted intent.
	IntentDigest string
}

func (s RenewalSource) certificate(now time.Time) (*x509.Certificate, error) {
	if !ValidDeviceID(s.DeviceID) || s.TenantID <= 0 || s.SiteID <= 0 || !ValidOrigin(s.Origin) || !validTarget(s.Platform, s.Architecture) || !nkeys.IsValidPublicUserKey(s.BrokerKey) || len(s.Certificate) == 0 || len(s.Certificate) > 16<<10 {
		return nil, ErrRenewalProof
	}
	c, err := x509.ParseCertificate(s.Certificate)
	if err != nil {
		return nil, ErrRenewalProof
	}
	key, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok || key.N == nil || key.N.BitLen() < 3072 || key.N.BitLen() > 4096 || key.E != 65537 || c.IsCA || !c.BasicConstraintsValid || c.Subject.CommonName != s.DeviceID || c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 || c.KeyUsage != x509.KeyUsageDigitalSignature || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(c.UnknownExtKeyUsage) != 0 || len(c.DNSNames) != 0 || len(c.IPAddresses) != 0 || len(c.EmailAddresses) != 0 || len(c.URIs) != 1 || c.URIs[0].String() != "urn:openuem:agent:"+s.DeviceID || c.NotBefore.After(now) || !c.NotAfter.After(now) || c.NotAfter.Sub(c.NotBefore) > 90*24*time.Hour+5*time.Minute {
		return nil, ErrRenewalProof
	}
	return c, nil
}

func (r RenewalRequest) validShape() bool {
	if len(r.SourceCertificateHash) != 64 {
		return false
	}
	hash, err := hex.DecodeString(r.SourceCertificateHash)
	return r.Version == RenewalVersion && r.Protocol == RenewalProtocol && ValidDeviceID(r.RequestID) && ValidDeviceID(r.DeviceID) && r.TenantID > 0 && r.SiteID > 0 && ValidOrigin(r.Origin) && validTarget(r.Platform, r.Architecture) && err == nil && len(hash) == 32 && hex.EncodeToString(hash) == r.SourceCertificateHash && nkeys.IsValidPublicUserKey(r.SourceBrokerKey) && nkeys.IsValidPublicUserKey(r.BrokerKey) && r.IssuedAt > 0 && len(r.CSR) > 0 && len(r.CSR) <= 12<<10 && len(r.CertificateProof) >= 512 && len(r.CertificateProof) <= 683 && len(r.SourceBrokerProof) == 86 && len(r.CandidateBrokerProof) == 86 && renewalBase64(r.CSR, base64.StdEncoding, 1, 9<<10) && renewalBase64(r.CertificateProof, base64.RawURLEncoding, 384, 512) && renewalBase64(r.SourceBrokerProof, base64.RawURLEncoding, 64, 64) && renewalBase64(r.CandidateBrokerProof, base64.RawURLEncoding, 64, 64)
}

// DecodeRenewalRequest enforces the wire grammar. Only ValidateRenewalProof with
// independently loaded current source state can authenticate the resulting value.
func DecodeRenewalRequest(data []byte) (*RenewalRequest, error) {
	var r RenewalRequest
	if len(data) > MaxRenewalRequestBytes || strictjson.Unmarshal(data, &r) != nil || !r.validShape() {
		return nil, ErrRenewalProof
	}
	return &r, nil
}

func renewalMessage(r RenewalRequest, role string) []byte {
	r.CertificateProof, r.SourceBrokerProof, r.CandidateBrokerProof = "", "", ""
	encoded, _ := json.Marshal(r)
	digest := sha256.Sum256(encoded)
	return append([]byte("openuem/agent/identity-renewal/"+role+"/v1\x00"), digest[:]...)
}

// NewRenewalRequest signs already-persisted endpoint keys. The caller must retain
// candidate keys and RequestID durably before transmission; this helper neither
// saves keys nor activates an issued identity. Same-key certificate renewal and
// fresh certificate/broker keys are both supported by the proof format.
func NewRenewalRequest(source RenewalSource, current, candidate *Keys, requestID string, now time.Time) (*RenewalRequest, error) {
	c, err := source.certificate(now)
	if err != nil || current == nil || candidate == nil || !validRenewalPrivateKey(current.Certificate) || current.Broker == nil || !validRenewalPrivateKey(candidate.Certificate) || candidate.Broker == nil || !ValidDeviceID(requestID) {
		return nil, ErrRenewalProof
	}
	if !current.Certificate.PublicKey.Equal(c.PublicKey) {
		return nil, ErrRenewalProof
	}
	oldBroker, err := current.Broker.PublicKey()
	if err != nil || oldBroker != source.BrokerKey {
		return nil, ErrRenewalProof
	}
	newBroker, err := candidate.Broker.PublicKey()
	if err != nil {
		return nil, ErrRenewalProof
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "OpenUEM agent identity renewal"}}, candidate.Certificate)
	if err != nil {
		return nil, ErrRenewalProof
	}
	hash := sha256.Sum256(source.Certificate)
	r := &RenewalRequest{Version: RenewalVersion, Protocol: RenewalProtocol, RequestID: requestID, DeviceID: source.DeviceID, TenantID: source.TenantID, SiteID: source.SiteID, Origin: source.Origin, Platform: source.Platform, Architecture: source.Architecture, SourceCertificateHash: hex.EncodeToString(hash[:]), SourceBrokerKey: source.BrokerKey, IssuedAt: now.Unix(), CSR: base64.StdEncoding.EncodeToString(csr), BrokerKey: newBroker}
	digest := sha256.Sum256(renewalMessage(*r, "source-certificate"))
	signature, err := rsa.SignPSS(rand.Reader, current.Certificate, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		return nil, ErrRenewalProof
	}
	r.CertificateProof = base64.RawURLEncoding.EncodeToString(signature)
	signature, err = current.Broker.Sign(renewalMessage(*r, "source-broker"))
	if err != nil {
		return nil, ErrRenewalProof
	}
	r.SourceBrokerProof = base64.RawURLEncoding.EncodeToString(signature)
	signature, err = candidate.Broker.Sign(renewalMessage(*r, "candidate-broker"))
	if err != nil {
		return nil, ErrRenewalProof
	}
	r.CandidateBrokerProof = base64.RawURLEncoding.EncodeToString(signature)
	if _, err := ValidateRenewalProof(*r, source, now); err != nil {
		return nil, err
	}
	return r, nil
}

func renewalSignature(value string, size int) ([]byte, error) {
	data, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(data) != size || base64.RawURLEncoding.EncodeToString(data) != value {
		return nil, ErrRenewalProof
	}
	return data, nil
}

func ValidateRenewalProof(r RenewalRequest, source RenewalSource, now time.Time) (*RenewalProof, error) {
	if !r.validShape() || r.DeviceID != source.DeviceID || r.TenantID != source.TenantID || r.SiteID != source.SiteID || r.Origin != source.Origin || r.Platform != source.Platform || r.Architecture != source.Architecture || r.SourceBrokerKey != source.BrokerKey || r.IssuedAt > now.Add(RenewalClockSkew).Unix() || r.IssuedAt < now.Add(-RenewalProofLifetime).Unix() {
		return nil, ErrRenewalProof
	}
	c, err := source.certificate(now)
	if err != nil {
		return nil, ErrRenewalProof
	}
	issued := time.Unix(r.IssuedAt, 0)
	if issued.Before(c.NotBefore) || !c.NotAfter.After(issued) {
		return nil, ErrRenewalProof
	}
	hash := sha256.Sum256(source.Certificate)
	if r.SourceCertificateHash != hex.EncodeToString(hash[:]) {
		return nil, ErrRenewalProof
	}
	der, err := base64.StdEncoding.Strict().DecodeString(r.CSR)
	if err != nil || base64.StdEncoding.EncodeToString(der) != r.CSR {
		return nil, ErrRenewalProof
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, ErrRenewalProof
	}
	key, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok || key.N == nil || key.N.BitLen() < 3072 || key.N.BitLen() > 4096 || key.E != 65537 || csr.SignatureAlgorithm != x509.SHA256WithRSA || csr.CheckSignature() != nil {
		return nil, ErrRenewalProof
	}
	oldKey := c.PublicKey.(*rsa.PublicKey)
	certificateProof, err := renewalSignature(r.CertificateProof, oldKey.Size())
	if err != nil {
		return nil, ErrRenewalProof
	}
	digest := sha256.Sum256(renewalMessage(r, "source-certificate"))
	if rsa.VerifyPSS(oldKey, crypto.SHA256, digest[:], certificateProof, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) != nil {
		return nil, ErrRenewalProof
	}
	for _, proof := range []struct{ key, signature, role string }{{source.BrokerKey, r.SourceBrokerProof, "source-broker"}, {r.BrokerKey, r.CandidateBrokerProof, "candidate-broker"}} {
		public, err := nkeys.FromPublicKey(proof.key)
		if err != nil {
			return nil, ErrRenewalProof
		}
		signature, err := renewalSignature(proof.signature, 64)
		if err != nil || public.Verify(renewalMessage(r, proof.role), signature) != nil {
			return nil, ErrRenewalProof
		}
	}
	encodedKey, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, ErrRenewalProof
	}
	binding := sha256.Sum256(append(append([]byte("openuem/agent/key-binding/v1\x00"), encodedKey...), []byte("\x00"+r.BrokerKey)...))
	// Use the validated public-key binding instead of CSR spelling or randomized
	// signature bytes, so fresh proofs can recover only the same pending intent.
	intent := r
	intent.CSR, intent.IssuedAt = hex.EncodeToString(binding[:]), 0
	intentHash := sha256.Sum256(renewalMessage(intent, "intent"))
	return &RenewalProof{PublicIdentity: PublicIdentity{CertificateKey: key, BrokerKey: r.BrokerKey, KeyBinding: hex.EncodeToString(binding[:])}, IntentDigest: hex.EncodeToString(intentHash[:])}, nil
}

func validRenewalPrivateKey(key *rsa.PrivateKey) bool {
	return key != nil && key.N != nil && key.D != nil && key.N.BitLen() >= 3072 && key.N.BitLen() <= 4096 && key.E == 65537 && key.Validate() == nil
}

func renewalBase64(value string, encoding *base64.Encoding, minimum, maximum int) bool {
	data, err := encoding.Strict().DecodeString(value)
	return err == nil && len(data) >= minimum && len(data) <= maximum && encoding.EncodeToString(data) == value
}
