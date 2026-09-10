package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/internal/strictjson"
)

type ResolvedIdentityRenewal = enrollment.ResolvedIdentityRenewal

type identityRenewalCancellationRecord struct {
	Version     int                          `json:"version"`
	Request     enrollment.RenewalResolution `json:"request"`
	CancelledAt time.Time                    `json:"cancelled_at"`
}

func (r *identityRenewalCancellationRecord) public() *ResolvedIdentityRenewal {
	return &ResolvedIdentityRenewal{Version: enrollment.RenewalVersion, ID: r.Request.RequestID, DeviceID: r.Request.DeviceID, SourceCertificateHash: r.Request.SourceCertificateHash, CertificateHash: r.Request.CertificateHash, Outcome: "cancelled", ResolvedAt: r.CancelledAt}
}

func identityRenewalCancellationPurpose(device, id string) string {
	return "identity-renewal-cancellation/v1/" + device + "/" + id
}

func (s *Store) identityRenewalCancellation(ctx context.Context, tx *sql.Tx, issuance *identityRenewalRecord, target enrollment.RenewalConfirmationTarget) (*identityRenewalCancellationRecord, error) {
	var device, sourceHash, hash string
	var encoded []byte
	var at time.Time
	err := tx.QueryRowContext(ctx, `SELECT device_id,source_certificate_hash,certificate_hash,encrypted_record,cancelled_at FROM uem_agent_identity_renewal_cancellations WHERE id=$1`, target.RequestID).Scan(&device, &sourceHash, &hash, &encoded, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if device != target.Candidate.DeviceID || len(encoded) > 16<<10 {
		return nil, ErrUnavailable
	}
	plain, err := s.open(encoded, identityRenewalCancellationPurpose(device, target.RequestID))
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(plain)
	var r identityRenewalCancellationRecord
	if strictjson.Unmarshal(plain, &r) != nil || r.Version != 1 || r.Request.SourceCertificateHash != sourceHash || r.Request.CertificateHash != hash || !r.CancelledAt.Equal(at) || at.Before(issuance.CreatedAt) || enrollment.ValidateResolvedIdentityRenewal(*r.public(), r.Request, target, issuance.source(), at) != nil {
		return nil, ErrUnavailable
	}
	return &r, nil
}

// ResolveIdentityRenewal recovers the exact committed activation, or permanently
// cancels an unconfirmed candidate while its original identity is still current
// and authorized. It never extends an expiry, switches generations, disconnects
// sessions or retires recovery work. Only its committed reply permits fallback.
func (s *Store) ResolveIdentityRenewal(ctx context.Context, request enrollment.RenewalResolution) (*ResolvedIdentityRenewal, error) {
	if s == nil || !enrollment.ValidDeviceID(request.DeviceID) || !enrollment.ValidDeviceID(request.RequestID) {
		return nil, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	current, err := loadIdentityRenewalCurrent(ctx, tx, request.DeviceID)
	if err != nil {
		return nil, err
	}
	now := s.identityRenewalTime()
	if err := current.validate(now); err != nil {
		return nil, err
	}
	records, err := s.identityRenewalRecords(ctx, tx, request.DeviceID)
	if err != nil {
		return nil, err
	}
	var issuance *identityRenewalRecord
	for i := range records {
		if records[i].Request.RequestID == request.RequestID {
			issuance = &records[i]
			break
		}
	}
	if issuance == nil {
		return nil, ErrDenied
	}
	target, _, err := issuance.confirmationTarget()
	if err != nil {
		return nil, err
	}
	c := target.Candidate
	if c.TenantID != current.source.TenantID || c.SiteID != current.source.SiteID || c.Origin != current.source.Origin || c.Platform != current.source.Platform || c.Architecture != current.source.Architecture || now.Before(issuance.CreatedAt) || enrollment.ValidateRenewalResolution(request, *target, now) != nil {
		return nil, ErrDenied
	}
	confirmed, err := s.identityRenewalConfirmation(ctx, tx, issuance, *target)
	if err != nil {
		return nil, err
	}
	cancelled, err := s.identityRenewalCancellation(ctx, tx, issuance, *target)
	if err != nil {
		return nil, err
	}
	if confirmed != nil && cancelled != nil {
		return nil, ErrUnavailable
	}
	var result *ResolvedIdentityRenewal
	if confirmed != nil {
		if current.hash != request.CertificateHash || current.source.BrokerKey != c.BrokerKey || now.Before(confirmed.ConfirmedAt) {
			return nil, ErrDenied
		}
		result = &ResolvedIdentityRenewal{Version: enrollment.RenewalVersion, ID: request.RequestID, DeviceID: request.DeviceID, SourceCertificateHash: request.SourceCertificateHash, CertificateHash: request.CertificateHash, Outcome: "confirmed", ResolvedAt: confirmed.ConfirmedAt}
	} else {
		if current.hash != target.SourceCertificateHash || current.source.BrokerKey != issuance.Request.SourceBrokerKey {
			return nil, ErrDenied
		}
		if cancelled != nil && now.Before(cancelled.CancelledAt) {
			return nil, ErrDenied
		}
		if cancelled == nil {
			at := s.identityRenewalTime()
			if at.Before(now) || current.validate(at) != nil || enrollment.ValidateRenewalResolution(request, *target, at) != nil {
				return nil, ErrDenied
			}
			cancelled = &identityRenewalCancellationRecord{Version: 1, Request: request, CancelledAt: at}
			plain, err := json.Marshal(cancelled)
			if err != nil || len(plain) > (16<<10)-64 {
				return nil, ErrUnavailable
			}
			defer clear(plain)
			encoded, err := s.seal(plain, identityRenewalCancellationPurpose(c.DeviceID, request.RequestID))
			if err != nil {
				return nil, ErrUnavailable
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO uem_agent_identity_renewal_cancellations(id,device_id,source_certificate_hash,certificate_hash,encrypted_record,cancelled_at) VALUES($1,$2,$3,$4,$5,$6)`, request.RequestID, c.DeviceID, request.SourceCertificateHash, request.CertificateHash, encoded, at); err != nil {
				return nil, err
			}
			if err := audit(ctx, tx, Scope{TenantID: c.TenantID, SiteID: c.SiteID}, "agent/"+c.DeviceID, "agent.identity.renew.cancel", request.RequestID); err != nil {
				return nil, err
			}
		}
		result = cancelled.public()
	}
	finalTime := s.identityRenewalTime()
	if finalTime.Before(now) || finalTime.Before(result.ResolvedAt) || current.validate(finalTime) != nil || enrollment.ValidateResolvedIdentityRenewal(*result, request, *target, issuance.source(), finalTime) != nil {
		return nil, ErrDenied
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}
