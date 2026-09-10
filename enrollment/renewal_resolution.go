package enrollment

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment/internal/strictjson"
)

const RenewalResolutionProtocol = "identity-renewal-resolution"
const MaxRenewalResolutionBytes = 8 << 10

var ErrRenewalResolution = errors.New("invalid individual-agent renewal resolution")

// RenewalResolution proves possession of both candidate keys for an atomic
// resolution: recover committed activation, or permanently cancel unconfirmed
// issuance. Its separate domain cannot authorize preparation or confirmation.
type RenewalResolution struct {
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
	CertificateHash       string `json:"certificate_hash"`
	BrokerKey             string `json:"broker_key"`
	IssuedAt              int64  `json:"issued_at"`
	CertificateProof      string `json:"certificate_proof"`
	BrokerProof           string `json:"broker_proof"`
}

func (r RenewalResolution) validShape() bool {
	return r.Version == RenewalVersion && r.Protocol == RenewalResolutionProtocol && ValidDeviceID(r.RequestID) && ValidDeviceID(r.DeviceID) && r.TenantID > 0 && r.SiteID > 0 && ValidOrigin(r.Origin) && validTarget(r.Platform, r.Architecture) && renewalHash(r.SourceCertificateHash) && renewalHash(r.CertificateHash) && nkeys.IsValidPublicUserKey(r.BrokerKey) && r.IssuedAt > 0 && len(r.CertificateProof) >= 512 && len(r.CertificateProof) <= 683 && len(r.BrokerProof) == 86 && renewalBase64(r.CertificateProof, base64.RawURLEncoding, 384, 512) && renewalBase64(r.BrokerProof, base64.RawURLEncoding, 64, 64)
}

func DecodeRenewalResolution(data []byte) (*RenewalResolution, error) {
	var r RenewalResolution
	if len(data) > MaxRenewalResolutionBytes || strictjson.Unmarshal(data, &r) != nil || !r.validShape() {
		return nil, ErrRenewalResolution
	}
	return &r, nil
}

func renewalResolutionMessage(r RenewalResolution, role string) []byte {
	r.CertificateProof, r.BrokerProof = "", ""
	encoded, _ := json.Marshal(r)
	digest := sha256.Sum256(encoded)
	return append([]byte("openuem/agent/identity-renewal-resolution/"+role+"/v1\x00"), digest[:]...)
}

// NewRenewalResolution binds the retained issuance and both candidate keys.
// Persist local confirmation uncertainty before sending. A lost response grants
// no fallback permission; retry the same target with a fresh resolution proof.
func NewRenewalResolution(target RenewalConfirmationTarget, keys *Keys, now time.Time) (*RenewalResolution, error) {
	s := target.Candidate
	c, err := s.certificate(now)
	if err != nil || !ValidDeviceID(target.RequestID) || !renewalHash(target.SourceCertificateHash) || keys == nil || !validRenewalPrivateKey(keys.Certificate) || keys.Broker == nil || !keys.Certificate.PublicKey.Equal(c.PublicKey) {
		return nil, ErrRenewalResolution
	}
	broker, err := keys.Broker.PublicKey()
	if err != nil || broker != s.BrokerKey {
		return nil, ErrRenewalResolution
	}
	hash := sha256.Sum256(c.Raw)
	r := &RenewalResolution{Version: RenewalVersion, Protocol: RenewalResolutionProtocol, RequestID: target.RequestID, DeviceID: s.DeviceID, TenantID: s.TenantID, SiteID: s.SiteID, Origin: s.Origin, Platform: s.Platform, Architecture: s.Architecture, SourceCertificateHash: target.SourceCertificateHash, CertificateHash: hex.EncodeToString(hash[:]), BrokerKey: s.BrokerKey, IssuedAt: now.Unix()}
	digest := sha256.Sum256(renewalResolutionMessage(*r, "candidate-certificate"))
	signature, err := rsa.SignPSS(rand.Reader, keys.Certificate, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		return nil, ErrRenewalResolution
	}
	r.CertificateProof = base64.RawURLEncoding.EncodeToString(signature)
	signature, err = keys.Broker.Sign(renewalResolutionMessage(*r, "candidate-broker"))
	if err != nil {
		return nil, ErrRenewalResolution
	}
	r.BrokerProof = base64.RawURLEncoding.EncodeToString(signature)
	if err := ValidateRenewalResolution(*r, target, now); err != nil {
		return nil, err
	}
	return r, nil
}

func ValidateRenewalResolution(r RenewalResolution, target RenewalConfirmationTarget, now time.Time) error {
	s := target.Candidate
	if !r.validShape() || r.RequestID != target.RequestID || r.SourceCertificateHash != target.SourceCertificateHash || r.DeviceID != s.DeviceID || r.TenantID != s.TenantID || r.SiteID != s.SiteID || r.Origin != s.Origin || r.Platform != s.Platform || r.Architecture != s.Architecture || r.BrokerKey != s.BrokerKey || r.IssuedAt > now.Add(RenewalClockSkew).Unix() || r.IssuedAt < now.Add(-RenewalProofLifetime).Unix() {
		return ErrRenewalResolution
	}
	c, err := s.certificate(now)
	if err != nil {
		return ErrRenewalResolution
	}
	issued := time.Unix(r.IssuedAt, 0)
	hash := sha256.Sum256(c.Raw)
	if issued.Before(c.NotBefore) || !c.NotAfter.After(issued) || r.CertificateHash != hex.EncodeToString(hash[:]) {
		return ErrRenewalResolution
	}
	key := c.PublicKey.(*rsa.PublicKey)
	proof, err := renewalSignature(r.CertificateProof, key.Size())
	if err != nil {
		return ErrRenewalResolution
	}
	digest := sha256.Sum256(renewalResolutionMessage(r, "candidate-certificate"))
	if rsa.VerifyPSS(key, crypto.SHA256, digest[:], proof, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) != nil {
		return ErrRenewalResolution
	}
	public, err := nkeys.FromPublicKey(s.BrokerKey)
	if err != nil {
		return ErrRenewalResolution
	}
	proof, err = renewalSignature(r.BrokerProof, 64)
	if err != nil || public.Verify(renewalResolutionMessage(r, "candidate-broker"), proof) != nil {
		return ErrRenewalResolution
	}
	return nil
}
