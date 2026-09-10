package registry

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/internal/strictjson"
)

const IdentityRenewalWindow = 30 * 24 * time.Hour
const IdentityRenewalPreparationLifetime = enrollment.RenewalPreparationLifetime
const MaxIdentityRenewals = 128

var ErrRenewalNotDue = errors.New("individual identity renewal is not due")
var ErrRenewalPending = errors.New("individual identity already has a pending renewal")

// PreparedIdentityRenewal contains only public issuance. Preparation does not
// authorize the candidate certificate/broker key or retire the current identity.
type PreparedIdentityRenewal = enrollment.PreparedIdentityRenewal

type identityRenewalRecord struct {
	Version           int                       `json:"version"`
	Request           enrollment.RenewalRequest `json:"request"`
	SourceCertificate []byte                    `json:"source_certificate"`
	Response          enrollment.Response       `json:"response"`
	CreatedAt         time.Time                 `json:"created_at"`
	ExpiresAt         time.Time                 `json:"expires_at"`
}

type identityRenewalCurrent struct {
	source                             enrollment.RenewalSource
	hash, keyHash, issuerOrigin        string
	expires                            time.Time
	authority, issuer, encryptedIssuer []byte
}

func (s *Store) identityRenewalTime() time.Time {
	if s.renewalClock != nil {
		return s.renewalClock().UTC().Truncate(time.Microsecond)
	}
	return time.Now().UTC().Truncate(time.Microsecond)
}

func loadIdentityRenewalCurrent(ctx context.Context, tx *sql.Tx, id string) (*identityRenewalCurrent, error) {
	c := &identityRenewalCurrent{}
	err := tx.QueryRowContext(ctx, `SELECT i.id,i.tenant_id,i.site_id,i.public_origin,i.platform,i.architecture,i.broker_key,i.certificate,i.certificate_hash,i.certificate_key_hash,i.certificate_expires_at,i.authority_certificate,a.public_origin,a.certificate,a.encrypted_key
 FROM uem_agent_identities i JOIN sites s ON s.id=i.site_id AND s.tenant_sites=i.tenant_id
 JOIN uem_agent_authorities a ON a.tenant_id=i.tenant_id
 WHERE i.id=$1 AND i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp()
 FOR UPDATE OF i FOR SHARE OF s,a`, id).Scan(&c.source.DeviceID, &c.source.TenantID, &c.source.SiteID, &c.source.Origin, &c.source.Platform, &c.source.Architecture, &c.source.BrokerKey, &c.source.Certificate, &c.hash, &c.keyHash, &c.expires, &c.authority, &c.issuerOrigin, &c.issuer, &c.encryptedIssuer)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDenied
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *identityRenewalCurrent) validate(now time.Time) error {
	if !c.expires.After(now) {
		return ErrDenied
	}
	certificate, err := x509.ParseCertificate(c.source.Certificate)
	if err != nil {
		return ErrDenied
	}
	key, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return ErrDenied
	}
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || digest(encoded) != c.keyHash || digest(c.source.Certificate) != c.hash || c.issuerOrigin != c.source.Origin {
		return ErrDenied
	}
	response := publicResponse(c.source.DeviceID, Scope{TenantID: c.source.TenantID, SiteID: c.source.SiteID}, c.source.Origin, c.source.Certificate, c.authority, c.expires)
	if _, err := enrollment.ValidateResponse(*response, c.source.Origin, key, now); err != nil {
		return ErrDenied
	}
	return nil
}

func (r *identityRenewalRecord) source() enrollment.RenewalSource {
	q := r.Request
	return enrollment.RenewalSource{DeviceID: q.DeviceID, TenantID: q.TenantID, SiteID: q.SiteID, Origin: q.Origin, Platform: q.Platform, Architecture: q.Architecture, BrokerKey: q.SourceBrokerKey, Certificate: r.SourceCertificate}
}

func (r *identityRenewalRecord) validate() (*enrollment.RenewalProof, error) {
	if r.Version != 1 || r.CreatedAt.IsZero() || !r.ExpiresAt.After(r.CreatedAt) || r.ExpiresAt.After(r.CreatedAt.Add(IdentityRenewalPreparationLifetime)) || len(r.SourceCertificate) > 16<<10 {
		return nil, ErrUnavailable
	}
	proof, err := enrollment.ValidateRenewalProof(r.Request, r.source(), r.CreatedAt)
	if err != nil {
		return nil, ErrUnavailable
	}
	certificate, err := enrollment.ValidateResponse(r.Response, r.Request.Origin, proof.CertificateKey, r.CreatedAt)
	if err != nil || r.Response.DeviceID != r.Request.DeviceID || r.Response.TenantID != r.Request.TenantID || r.Response.SiteID != r.Request.SiteID {
		return nil, ErrUnavailable
	}
	source, err := x509.ParseCertificate(r.SourceCertificate)
	if err != nil || r.ExpiresAt.After(source.NotAfter) || !certificate.NotAfter.After(source.NotAfter.Add(24*time.Hour)) {
		return nil, ErrUnavailable
	}
	return proof, nil
}

func (r *identityRenewalRecord) public() *PreparedIdentityRenewal {
	return &PreparedIdentityRenewal{ID: r.Request.RequestID, SourceCertificateHash: r.Request.SourceCertificateHash, ExpiresAt: r.ExpiresAt, Response: r.Response}
}

func identityRenewalPurpose(device, id string) string {
	return "identity-renewal/v1/" + device + "/" + id
}

func (s *Store) identityRenewalRecords(ctx context.Context, tx *sql.Tx, device string) ([]identityRenewalRecord, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,tenant_id,site_id,source_certificate_hash,certificate_hash,intent_digest,encrypted_record,created_at,expires_at FROM uem_agent_identity_renewals WHERE device_id=$1 ORDER BY created_at,id LIMIT $2`, device, MaxIdentityRenewals+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []identityRenewalRecord{}
	for rows.Next() {
		var id, sourceHash, certificateHash, intent string
		var tenant, site int
		var encoded []byte
		var created, expires time.Time
		if err := rows.Scan(&id, &tenant, &site, &sourceHash, &certificateHash, &intent, &encoded, &created, &expires); err != nil {
			return nil, err
		}
		if len(records) >= MaxIdentityRenewals || len(encoded) > 256<<10 {
			return nil, ErrUnavailable
		}
		plain, err := s.open(encoded, identityRenewalPurpose(device, id))
		if err != nil {
			return nil, ErrUnavailable
		}
		var r identityRenewalRecord
		err = strictjson.Unmarshal(plain, &r)
		clear(plain)
		if err != nil {
			return nil, ErrUnavailable
		}
		proof, err := r.validate()
		if err != nil || r.Request.RequestID != id || r.Request.DeviceID != device || r.Request.TenantID != tenant || r.Request.SiteID != site || r.Request.SourceCertificateHash != sourceHash || proof.IntentDigest != intent || !r.CreatedAt.Equal(created) || !r.ExpiresAt.Equal(expires) {
			return nil, ErrUnavailable
		}
		certificate, err := enrollment.ValidateResponse(r.Response, r.Request.Origin, proof.CertificateKey, r.CreatedAt)
		if err != nil || digest(certificate.Raw) != certificateHash {
			return nil, ErrUnavailable
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

func reserveIdentityRenewalKeys(ctx context.Context, tx *sql.Tx, device string, proof *enrollment.RenewalProof) error {
	encoded, err := x509.MarshalPKIXPublicKey(proof.CertificateKey)
	if err != nil {
		return ErrUnavailable
	}
	for _, key := range [][2]string{{"certificate", digest(encoded)}, {"broker", proof.BrokerKey}} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO uem_agent_key_reservations(kind,key_value,device_id) VALUES($1,$2,$3) ON CONFLICT(kind,key_value) DO NOTHING`, key[0], key[1], device); err != nil {
			return err
		}
		var owner string
		if err := tx.QueryRowContext(ctx, `SELECT device_id FROM uem_agent_key_reservations WHERE kind=$1 AND key_value=$2`, key[0], key[1]).Scan(&owner); err != nil {
			return err
		}
		if owner != device {
			return ErrDenied
		}
	}
	return nil
}

// PrepareIdentityRenewal retains the original identity, certificate and broker
// authorization. The candidate is only reserved/issued; a separate verified
// handoff must activate it. Responses are released only after committed audit.
func (s *Store) PrepareIdentityRenewal(ctx context.Context, request enrollment.RenewalRequest) (*PreparedIdentityRenewal, error) {
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
	proof, err := enrollment.ValidateRenewalProof(request, current.source, now)
	if err != nil {
		return nil, ErrDenied
	}
	records, err := s.identityRenewalRecords(ctx, tx, request.DeviceID)
	if err != nil {
		return nil, err
	}
	cancellations := make(map[string]bool, len(records))
	for i := range records {
		r := &records[i]
		target, _, err := r.confirmationTarget()
		if err != nil {
			return nil, err
		}
		cancelled, err := s.identityRenewalCancellation(ctx, tx, r, *target)
		if err != nil {
			return nil, err
		}
		if cancelled != nil {
			confirmed, err := s.identityRenewalConfirmation(ctx, tx, r, *target)
			if err != nil {
				return nil, err
			}
			if confirmed != nil {
				return nil, ErrUnavailable
			}
			if now.Before(cancelled.CancelledAt) {
				return nil, ErrDenied
			}
			cancellations[r.Request.RequestID] = true
		}
	}
	for i := range records {
		r := &records[i]
		if r.Request.RequestID == request.RequestID {
			if cancellations[r.Request.RequestID] {
				return nil, ErrDenied
			}
			previous, err := r.validate()
			if err != nil || previous.IntentDigest != proof.IntentDigest || !r.ExpiresAt.After(now) || now.Before(r.CreatedAt) {
				return nil, ErrDenied
			}
			if _, err := enrollment.ValidateRenewalProof(request, current.source, s.identityRenewalTime()); err != nil {
				return nil, ErrDenied
			}
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return r.public(), nil
		}
	}
	for i := range records {
		r := &records[i]
		if r.Request.SourceCertificateHash == current.hash && r.ExpiresAt.After(now) && !cancellations[r.Request.RequestID] {
			return nil, ErrRenewalPending
		}
	}
	if len(records) >= MaxIdentityRenewals {
		return nil, ErrUnavailable
	}
	if current.expires.After(now.Add(IdentityRenewalWindow)) {
		return nil, ErrRenewalNotDue
	}
	if !current.expires.After(now.Add(5 * time.Minute)) {
		return nil, ErrDenied
	}
	if err := reserveIdentityRenewalKeys(ctx, tx, request.DeviceID, proof); err != nil {
		return nil, err
	}
	private, err := s.open(current.encryptedIssuer, fmt.Sprintf("%d/authority/key", current.source.TenantID))
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(private)
	ca, signer, err := parseAuthority(current.issuer, private)
	if err != nil {
		return nil, ErrUnavailable
	}
	certificate, certificateExpires, err := issueCertificateAt(ca, signer, request.DeviceID, proof.CertificateKey, now)
	if err != nil {
		return nil, ErrUnavailable
	}
	expires := now.Add(IdentityRenewalPreparationLifetime)
	if current.expires.Before(expires) {
		expires = current.expires
	}
	r := identityRenewalRecord{Version: 1, Request: request, SourceCertificate: current.source.Certificate, Response: *publicResponse(request.DeviceID, Scope{TenantID: current.source.TenantID, SiteID: current.source.SiteID}, current.source.Origin, certificate, current.issuer, certificateExpires), CreatedAt: now, ExpiresAt: expires}
	if _, err := r.validate(); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(r)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(plain)
	if len(plain) > 256<<10-64 {
		return nil, ErrUnavailable
	}
	encoded, err := s.seal(plain, identityRenewalPurpose(request.DeviceID, request.RequestID))
	if err != nil {
		return nil, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO uem_agent_identity_renewals(id,device_id,tenant_id,site_id,source_certificate_hash,certificate_hash,intent_digest,encrypted_record,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, request.RequestID, request.DeviceID, current.source.TenantID, current.source.SiteID, current.hash, digest(certificate), proof.IntentDigest, encoded, now, expires); err != nil {
		var state interface{ SQLState() string }
		if errors.As(err, &state) && state.SQLState() == "23505" {
			return nil, ErrDenied
		}
		return nil, err
	}
	if err := audit(ctx, tx, Scope{TenantID: current.source.TenantID, SiteID: current.source.SiteID}, "agent/"+request.DeviceID, "agent.identity.renew.prepare", request.RequestID); err != nil {
		return nil, err
	}
	if _, err := enrollment.ValidateRenewalProof(request, current.source, s.identityRenewalTime()); err != nil {
		return nil, ErrDenied
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.public(), nil
}
