package registry

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/internal/strictjson"
)

var ErrRenewalRecoveryPending = errors.New("identity renewal requires recovery task reconciliation")

type ConfirmedIdentityRenewal = enrollment.ConfirmedIdentityRenewal

type identityRenewalConfirmationRecord struct {
	Version     int                            `json:"version"`
	Request     enrollment.RenewalConfirmation `json:"request"`
	ConfirmedAt time.Time                      `json:"confirmed_at"`
}

func (r *identityRenewalConfirmationRecord) public() *ConfirmedIdentityRenewal {
	return &ConfirmedIdentityRenewal{ID: r.Request.RequestID, DeviceID: r.Request.DeviceID, CertificateHash: r.Request.CertificateHash, ConfirmedAt: r.ConfirmedAt}
}

func (r *identityRenewalRecord) confirmationTarget() (*enrollment.RenewalConfirmationTarget, *enrollment.RenewalProof, error) {
	proof, err := r.validate()
	if err != nil {
		return nil, nil, err
	}
	certificate, err := enrollment.ValidateResponse(r.Response, r.Request.Origin, proof.CertificateKey, r.CreatedAt)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	candidate := r.source()
	candidate.Certificate, candidate.BrokerKey = certificate.Raw, proof.BrokerKey
	return &enrollment.RenewalConfirmationTarget{RequestID: r.Request.RequestID, SourceCertificateHash: r.Request.SourceCertificateHash, Candidate: candidate}, proof, nil
}

func identityRenewalConfirmationPurpose(device, id string) string {
	return "identity-renewal-confirmation/v1/" + device + "/" + id
}

func (s *Store) identityRenewalConfirmation(ctx context.Context, tx *sql.Tx, issuance *identityRenewalRecord, target enrollment.RenewalConfirmationTarget) (*identityRenewalConfirmationRecord, error) {
	var device, hash string
	var encoded []byte
	var at time.Time
	err := tx.QueryRowContext(ctx, `SELECT device_id,certificate_hash,encrypted_record,confirmed_at FROM uem_agent_identity_renewal_confirmations WHERE id=$1`, target.RequestID).Scan(&device, &hash, &encoded, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if device != target.Candidate.DeviceID || len(encoded) > 16<<10 {
		return nil, ErrUnavailable
	}
	plain, err := s.open(encoded, identityRenewalConfirmationPurpose(device, target.RequestID))
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(plain)
	var r identityRenewalConfirmationRecord
	if strictjson.Unmarshal(plain, &r) != nil || r.Version != 1 || r.Request.CertificateHash != hash || !r.ConfirmedAt.Equal(at) || at.Before(issuance.CreatedAt) || !at.Before(issuance.ExpiresAt) || enrollment.ValidateRenewalConfirmation(r.Request, target, at) != nil {
		return nil, ErrUnavailable
	}
	return &r, nil
}

// ConfirmIdentityRenewal atomically activates previously issued candidate keys,
// preserves the device/scope and schedules bounded old-session disconnection.
// Its reply may be lost after commit; a fresh proof recovers the same committed
// result only while that exact generation remains current and authorized.
func (s *Store) ConfirmIdentityRenewal(ctx context.Context, request enrollment.RenewalConfirmation) (*ConfirmedIdentityRenewal, error) {
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
	target, proof, err := issuance.confirmationTarget()
	if err != nil {
		return nil, err
	}
	c := target.Candidate
	if c.TenantID != current.source.TenantID || c.SiteID != current.source.SiteID || c.Origin != current.source.Origin || c.Platform != current.source.Platform || c.Architecture != current.source.Architecture || enrollment.ValidateRenewalConfirmation(request, *target, now) != nil {
		return nil, ErrDenied
	}
	previous, err := s.identityRenewalConfirmation(ctx, tx, issuance, *target)
	if err != nil {
		return nil, err
	}
	cancelled, err := s.identityRenewalCancellation(ctx, tx, issuance, *target)
	if err != nil {
		return nil, err
	}
	if cancelled != nil {
		if previous != nil {
			return nil, ErrUnavailable
		}
		return nil, ErrDenied
	}
	if previous != nil {
		if current.hash != request.CertificateHash || current.source.BrokerKey != c.BrokerKey || now.Before(previous.ConfirmedAt) {
			return nil, ErrDenied
		}
		if err := enrollment.ValidateRenewalConfirmation(request, *target, s.identityRenewalTime()); err != nil {
			return nil, ErrDenied
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return previous.public(), nil
	}
	if current.hash != target.SourceCertificateHash || current.source.BrokerKey != issuance.Request.SourceBrokerKey || !issuance.ExpiresAt.After(now) || now.Before(issuance.CreatedAt) {
		return nil, ErrDenied
	}
	// Delivered mutations must not lose their unresolved receipt when the existing
	// certificate-change triggers retire recovery tasks. Cancelled/expired delivered
	// mutations also block; a status label is not evidence that execution stopped.
	// Delivered read-only requests can finish first; undelivered work is cancelled
	// atomically by the existing epoch triggers and must be queued afresh afterward.
	if err := s.identityRenewalRotationGuard(ctx, tx, current); err != nil {
		return nil, err
	}
	var recoveryPending bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_recovery_tasks WHERE device_id=$1 AND delivered_at IS NOT NULL AND status='pending')`, request.DeviceID).Scan(&recoveryPending)
	if err != nil {
		return nil, err
	}
	if recoveryPending {
		return nil, ErrRenewalRecoveryPending
	}
	leaf, err := enrollment.ValidateResponse(issuance.Response, c.Origin, proof.CertificateKey, now)
	if err != nil {
		return nil, ErrDenied
	}
	// A concurrent authority replacement does not implicitly approve old pending
	// issuance. Authority rotation must define its own explicit transition policy.
	response := publicResponse(c.DeviceID, Scope{TenantID: c.TenantID, SiteID: c.SiteID}, c.Origin, leaf.Raw, current.issuer, leaf.NotAfter)
	if response.Authority != issuance.Response.Authority || !bytes.Equal(leaf.Raw, c.Certificate) {
		return nil, ErrDenied
	}
	if err := reserveIdentityRenewalKeys(ctx, tx, c.DeviceID, proof); err != nil {
		return nil, err
	}
	encodedKey, err := x509.MarshalPKIXPublicKey(proof.CertificateKey)
	if err != nil {
		return nil, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, `UPDATE uem_agent_identities SET key_binding=$2,certificate_key_hash=$3,broker_key=$4,certificate=$5,authority_certificate=$6,certificate_hash=$7,certificate_expires_at=$8 WHERE id=$1`, c.DeviceID, proof.KeyBinding, digest(encodedKey), proof.BrokerKey, leaf.Raw, current.issuer, digest(leaf.Raw), leaf.NotAfter); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE uem_agent_broker_sessions SET disconnect_at=COALESCE(disconnect_at,clock_timestamp()) WHERE device_id=$1 AND expires_at>clock_timestamp()`, c.DeviceID); err != nil {
		return nil, err
	}
	// A recipient must register a new server epoch against the new certificate.
	// This does not delete immutable task history or any endpoint-local keys.
	if _, err := tx.ExecContext(ctx, `DELETE FROM uem_agent_recovery_recipients WHERE device_id=$1`, c.DeviceID); err != nil {
		return nil, err
	}
	at := s.identityRenewalTime()
	if at.Before(issuance.CreatedAt) || !issuance.ExpiresAt.After(at) || enrollment.ValidateRenewalConfirmation(request, *target, at) != nil {
		return nil, ErrDenied
	}
	record := identityRenewalConfirmationRecord{Version: 1, Request: request, ConfirmedAt: at}
	plain, err := json.Marshal(record)
	if err != nil || len(plain) > (16<<10)-64 {
		return nil, ErrUnavailable
	}
	defer clear(plain)
	encoded, err := s.seal(plain, identityRenewalConfirmationPurpose(c.DeviceID, request.RequestID))
	if err != nil {
		return nil, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO uem_agent_identity_renewal_confirmations(id,device_id,certificate_hash,encrypted_record,confirmed_at) VALUES($1,$2,$3,$4,$5)`, request.RequestID, c.DeviceID, request.CertificateHash, encoded, at); err != nil {
		return nil, err
	}
	if err := audit(ctx, tx, Scope{TenantID: c.TenantID, SiteID: c.SiteID}, "agent/"+c.DeviceID, "agent.identity.renew.confirm", request.RequestID); err != nil {
		return nil, err
	}
	finalTime := s.identityRenewalTime()
	if finalTime.Before(at) || !issuance.ExpiresAt.After(finalTime) || enrollment.ValidateRenewalConfirmation(request, *target, finalTime) != nil {
		return nil, ErrDenied
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return record.public(), nil
}
