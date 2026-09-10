package enrollment

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/open-uem/nats/enrollment/internal/strictjson"
)

const RenewalPreparationLifetime = 7 * 24 * time.Hour
const MaxPreparedIdentityRenewalBytes = 96 << 10
const MaxConfirmedIdentityRenewalBytes = 2 << 10

var (
	ErrIdentityRenewalNotDue          = errors.New("individual identity renewal is not due")
	ErrIdentityRenewalPending         = errors.New("individual identity already has a pending renewal")
	ErrIdentityRenewalRecoveryPending = errors.New("individual identity renewal requires recovery reconciliation")
	ErrIdentityRenewalDenied          = errors.New("individual identity renewal is not authorized")
)

// PreparedIdentityRenewal is authenticated public issuance, not activation.
// No endpoint private key belongs in this response or its JSON representation.
type PreparedIdentityRenewal struct {
	ID                    string    `json:"id"`
	SourceCertificateHash string    `json:"source_certificate_hash"`
	ExpiresAt             time.Time `json:"expires_at"`
	Response              Response  `json:"response"`
}

type ConfirmedIdentityRenewal struct {
	ID              string    `json:"id"`
	DeviceID        string    `json:"device_id"`
	CertificateHash string    `json:"certificate_hash"`
	ConfirmedAt     time.Time `json:"confirmed_at"`
}

// RenewalConflict is a fixed public conflict code. It contains no diagnostic,
// request body, private key, device identifier or caller-controlled message.
type RenewalConflict struct {
	Version int    `json:"version"`
	Code    string `json:"code"`
}

func (r RenewalConflict) ErrorValue() error {
	if r.Version != RenewalVersion {
		return ErrInvalidResponse
	}
	switch r.Code {
	case "not_due":
		return ErrIdentityRenewalNotDue
	case "pending":
		return ErrIdentityRenewalPending
	case "recovery_pending":
		return ErrIdentityRenewalRecoveryPending
	default:
		return ErrInvalidResponse
	}
}

func DecodePreparedIdentityRenewal(data []byte) (*PreparedIdentityRenewal, error) {
	var r PreparedIdentityRenewal
	if len(data) > MaxPreparedIdentityRenewalBytes || strictjson.Unmarshal(data, &r) != nil || !ValidDeviceID(r.ID) || !renewalHash(r.SourceCertificateHash) || r.ExpiresAt.IsZero() {
		return nil, ErrInvalidResponse
	}
	return &r, nil
}

func DecodeConfirmedIdentityRenewal(data []byte) (*ConfirmedIdentityRenewal, error) {
	var r ConfirmedIdentityRenewal
	if len(data) > MaxConfirmedIdentityRenewalBytes || strictjson.Unmarshal(data, &r) != nil || !ValidDeviceID(r.ID) || !ValidDeviceID(r.DeviceID) || !renewalHash(r.CertificateHash) || r.ConfirmedAt.IsZero() {
		return nil, ErrInvalidResponse
	}
	return &r, nil
}

// ValidatePreparedIdentityRenewal binds a server-authenticated response to the
// exact fresh request, original identity and candidate key proof. Its returned
// target may be confirmed only after issuance and candidate keys are durable.
func ValidatePreparedIdentityRenewal(r PreparedIdentityRenewal, request RenewalRequest, source RenewalSource, now time.Time) (*RenewalConfirmationTarget, error) {
	proof, err := ValidateRenewalProof(request, source, now)
	if err != nil || r.ID != request.RequestID || r.SourceCertificateHash != request.SourceCertificateHash || !r.ExpiresAt.After(now) || r.ExpiresAt.After(now.Add(RenewalPreparationLifetime+RenewalClockSkew)) || r.Response.DeviceID != source.DeviceID || r.Response.TenantID != source.TenantID || r.Response.SiteID != source.SiteID {
		return nil, ErrInvalidResponse
	}
	old, err := source.certificate(now)
	if err != nil || r.ExpiresAt.After(old.NotAfter) {
		return nil, ErrInvalidResponse
	}
	certificate, err := ValidateResponse(r.Response, source.Origin, proof.CertificateKey, now)
	if err != nil || !certificate.NotAfter.After(old.NotAfter.Add(24*time.Hour)) {
		return nil, ErrInvalidResponse
	}
	candidate := source
	candidate.Certificate, candidate.BrokerKey = certificate.Raw, proof.BrokerKey
	return &RenewalConfirmationTarget{RequestID: r.ID, SourceCertificateHash: r.SourceCertificateHash, Candidate: candidate}, nil
}

func ValidateConfirmedIdentityRenewal(r ConfirmedIdentityRenewal, request RenewalConfirmation, target RenewalConfirmationTarget, now time.Time) error {
	if ValidateRenewalConfirmation(request, target, now) != nil || r.ID != request.RequestID || r.DeviceID != request.DeviceID || r.CertificateHash != request.CertificateHash || r.ConfirmedAt.IsZero() || r.ConfirmedAt.After(now.Add(RenewalClockSkew)) {
		return ErrInvalidResponse
	}
	certificate, err := target.Candidate.certificate(now)
	if err != nil || r.ConfirmedAt.Before(certificate.NotBefore) || !r.ConfirmedAt.Before(certificate.NotAfter) {
		return ErrInvalidResponse
	}
	hash := sha256.Sum256(certificate.Raw)
	if r.CertificateHash != hex.EncodeToString(hash[:]) {
		return ErrInvalidResponse
	}
	return nil
}

func IdentityRenewalPath(deviceID, operation string) string {
	if !ValidDeviceID(deviceID) || (operation != "prepare" && operation != "confirm" && operation != "resolve") {
		return ""
	}
	return "/enroll/desktop/identities/" + deviceID + "/renewal/" + operation
}
