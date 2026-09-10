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

const RenewalConfirmationProtocol = "identity-renewal-confirmation"
const MaxRenewalConfirmationBytes = 8 << 10

var ErrRenewalConfirmation = errors.New("invalid individual-agent renewal confirmation")

// RenewalConfirmationTarget comes from authenticated, persisted issuance. A
// service must never derive it from peer-supplied certificates or request fields.
type RenewalConfirmationTarget struct {
	RequestID, SourceCertificateHash string
	Candidate                        RenewalSource
}

// RenewalConfirmation proves possession of both candidate keys and binds the
// exact issued certificate. It has a separate protocol/domain from preparation;
// replay safety and current-generation checks belong to the persistent service.
type RenewalConfirmation struct {
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

func renewalHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	data, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(data) == value
}

func (r RenewalConfirmation) validShape() bool {
	return r.Version == RenewalVersion && r.Protocol == RenewalConfirmationProtocol && ValidDeviceID(r.RequestID) && ValidDeviceID(r.DeviceID) && r.TenantID > 0 && r.SiteID > 0 && ValidOrigin(r.Origin) && validTarget(r.Platform, r.Architecture) && renewalHash(r.SourceCertificateHash) && renewalHash(r.CertificateHash) && nkeys.IsValidPublicUserKey(r.BrokerKey) && r.IssuedAt > 0 && len(r.CertificateProof) >= 512 && len(r.CertificateProof) <= 683 && len(r.BrokerProof) == 86 && renewalBase64(r.CertificateProof, base64.RawURLEncoding, 384, 512) && renewalBase64(r.BrokerProof, base64.RawURLEncoding, 64, 64)
}

func DecodeRenewalConfirmation(data []byte) (*RenewalConfirmation, error) {
	var r RenewalConfirmation
	if len(data) > MaxRenewalConfirmationBytes || strictjson.Unmarshal(data, &r) != nil || !r.validShape() {
		return nil, ErrRenewalConfirmation
	}
	return &r, nil
}

func renewalConfirmationMessage(r RenewalConfirmation, role string) []byte {
	r.CertificateProof, r.BrokerProof = "", ""
	encoded, _ := json.Marshal(r)
	digest := sha256.Sum256(encoded)
	return append([]byte("openuem/agent/identity-renewal-confirmation/"+role+"/v1\x00"), digest[:]...)
}

// NewRenewalConfirmation requires candidate keys and issuance to be durably
// stored first. After sending it, a lost reply may mean activation committed:
// retry the same target with a fresh proof instead of reverting to old keys.
func NewRenewalConfirmation(target RenewalConfirmationTarget, keys *Keys, now time.Time) (*RenewalConfirmation, error) {
	s := target.Candidate
	c, err := s.certificate(now)
	if err != nil || !ValidDeviceID(target.RequestID) || !renewalHash(target.SourceCertificateHash) || keys == nil || !validRenewalPrivateKey(keys.Certificate) || keys.Broker == nil || !keys.Certificate.PublicKey.Equal(c.PublicKey) {
		return nil, ErrRenewalConfirmation
	}
	broker, err := keys.Broker.PublicKey()
	if err != nil || broker != s.BrokerKey {
		return nil, ErrRenewalConfirmation
	}
	hash := sha256.Sum256(c.Raw)
	r := &RenewalConfirmation{Version: RenewalVersion, Protocol: RenewalConfirmationProtocol, RequestID: target.RequestID, DeviceID: s.DeviceID, TenantID: s.TenantID, SiteID: s.SiteID, Origin: s.Origin, Platform: s.Platform, Architecture: s.Architecture, SourceCertificateHash: target.SourceCertificateHash, CertificateHash: hex.EncodeToString(hash[:]), BrokerKey: s.BrokerKey, IssuedAt: now.Unix()}
	digest := sha256.Sum256(renewalConfirmationMessage(*r, "candidate-certificate"))
	signature, err := rsa.SignPSS(rand.Reader, keys.Certificate, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		return nil, ErrRenewalConfirmation
	}
	r.CertificateProof = base64.RawURLEncoding.EncodeToString(signature)
	signature, err = keys.Broker.Sign(renewalConfirmationMessage(*r, "candidate-broker"))
	if err != nil {
		return nil, ErrRenewalConfirmation
	}
	r.BrokerProof = base64.RawURLEncoding.EncodeToString(signature)
	if err := ValidateRenewalConfirmation(*r, target, now); err != nil {
		return nil, err
	}
	return r, nil
}

func ValidateRenewalConfirmation(r RenewalConfirmation, target RenewalConfirmationTarget, now time.Time) error {
	s := target.Candidate
	if !r.validShape() || r.RequestID != target.RequestID || r.SourceCertificateHash != target.SourceCertificateHash || r.DeviceID != s.DeviceID || r.TenantID != s.TenantID || r.SiteID != s.SiteID || r.Origin != s.Origin || r.Platform != s.Platform || r.Architecture != s.Architecture || r.BrokerKey != s.BrokerKey || r.IssuedAt > now.Add(RenewalClockSkew).Unix() || r.IssuedAt < now.Add(-RenewalProofLifetime).Unix() {
		return ErrRenewalConfirmation
	}
	c, err := s.certificate(now)
	if err != nil {
		return ErrRenewalConfirmation
	}
	issued := time.Unix(r.IssuedAt, 0)
	hash := sha256.Sum256(c.Raw)
	if issued.Before(c.NotBefore) || !c.NotAfter.After(issued) || r.CertificateHash != hex.EncodeToString(hash[:]) {
		return ErrRenewalConfirmation
	}
	key := c.PublicKey.(*rsa.PublicKey)
	proof, err := renewalSignature(r.CertificateProof, key.Size())
	if err != nil {
		return ErrRenewalConfirmation
	}
	digest := sha256.Sum256(renewalConfirmationMessage(r, "candidate-certificate"))
	if rsa.VerifyPSS(key, crypto.SHA256, digest[:], proof, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) != nil {
		return ErrRenewalConfirmation
	}
	public, err := nkeys.FromPublicKey(s.BrokerKey)
	if err != nil {
		return ErrRenewalConfirmation
	}
	proof, err = renewalSignature(r.BrokerProof, 64)
	if err != nil || public.Verify(renewalConfirmationMessage(r, "candidate-broker"), proof) != nil {
		return ErrRenewalConfirmation
	}
	return nil
}
