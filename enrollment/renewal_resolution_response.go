package enrollment

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"time"

	"github.com/open-uem/nats/enrollment/internal/strictjson"
)

const MaxResolvedIdentityRenewalBytes = 2 << 10

// ResolvedIdentityRenewal is an authenticated immutable server outcome. For
// confirmed it retains the original activation time; for cancelled the candidate
// is permanently disabled. It does not grant permission to use expired/revoked
// credentials or replace the endpoint's protected generation selection.
type ResolvedIdentityRenewal struct {
	Version               int       `json:"version"`
	ID                    string    `json:"id"`
	DeviceID              string    `json:"device_id"`
	SourceCertificateHash string    `json:"source_certificate_hash"`
	CertificateHash       string    `json:"certificate_hash"`
	Outcome               string    `json:"outcome"`
	ResolvedAt            time.Time `json:"resolved_at"`
}

func DecodeResolvedIdentityRenewal(data []byte) (*ResolvedIdentityRenewal, error) {
	var r ResolvedIdentityRenewal
	if len(data) > MaxResolvedIdentityRenewalBytes || strictjson.Unmarshal(data, &r) != nil || r.Version != RenewalVersion || !ValidDeviceID(r.ID) || !ValidDeviceID(r.DeviceID) || !renewalHash(r.SourceCertificateHash) || !renewalHash(r.CertificateHash) || (r.Outcome != "confirmed" && r.Outcome != "cancelled") || r.ResolvedAt.IsZero() {
		return nil, ErrInvalidResponse
	}
	return &r, nil
}

// ValidateResolvedIdentityRenewal checks exact retained source/target bindings.
// Current source validity is checked separately before actually using its keys:
// a response can arrive after source expiry, and a restored old generation must
// never be treated as newly enrolled or receive a renewed expiry here.
func ValidateResolvedIdentityRenewal(r ResolvedIdentityRenewal, request RenewalResolution, target RenewalConfirmationTarget, source RenewalSource, now time.Time) error {
	if ValidateRenewalResolution(request, target, now) != nil || r.Version != RenewalVersion || r.ID != request.RequestID || r.DeviceID != request.DeviceID || r.SourceCertificateHash != request.SourceCertificateHash || r.CertificateHash != request.CertificateHash || (r.Outcome != "confirmed" && r.Outcome != "cancelled") || r.ResolvedAt.IsZero() || r.ResolvedAt.After(now.Add(RenewalClockSkew)) {
		return ErrInvalidResponse
	}
	candidate, err := target.Candidate.certificate(now)
	if err != nil || r.ResolvedAt.Before(candidate.NotBefore) || !r.ResolvedAt.Before(candidate.NotAfter) {
		return ErrInvalidResponse
	}
	if renewalResolutionSource(target, source) != nil {
		return ErrInvalidResponse
	}
	if _, err := source.certificate(r.ResolvedAt); err != nil {
		return ErrInvalidResponse
	}
	return nil
}

func renewalResolutionSource(target RenewalConfirmationTarget, source RenewalSource) error {
	if len(source.Certificate) > 16<<10 {
		return ErrInvalidResponse
	}
	hash := sha256.Sum256(source.Certificate)
	s := target.Candidate
	if hex.EncodeToString(hash[:]) != target.SourceCertificateHash || source.DeviceID != s.DeviceID || source.TenantID != s.TenantID || source.SiteID != s.SiteID || source.Origin != s.Origin || source.Platform != s.Platform || source.Architecture != s.Architecture {
		return ErrInvalidResponse
	}
	certificate, err := x509.ParseCertificate(source.Certificate)
	if err != nil {
		return ErrInvalidResponse
	}
	if _, err := source.certificate(certificate.NotBefore); err != nil {
		return ErrInvalidResponse
	}
	return nil
}
