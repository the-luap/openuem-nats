package registry

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"time"

	"github.com/open-uem/nats/enrollment"
)

func (s *AccessStore) SoftwareReady(ctx context.Context) bool {
	var ready bool
	err := s.db.QueryRowContext(ctx, `SELECT to_regclass('uem_agent_software_recipients') IS NOT NULL AND to_regclass('uem_agent_software_challenges') IS NOT NULL AND to_regclass('uem_agent_software_tasks') IS NOT NULL`).Scan(&ready)
	return err == nil && ready
}
func softwareCertificate(raw []byte) (*x509.Certificate, error) {
	if len(raw) == 0 || len(raw) > 16384 {
		return nil, ErrDenied
	}
	if block, rest := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, ErrDenied
		}
		raw = block.Bytes
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, ErrDenied
	}
	return cert, nil
}

// SoftwareIdentity takes the same identity-before-inventory lock order as the
// private worker. Callers must hold these locks until their final audit commit.
func (s *AccessStore) SoftwareIdentity(ctx context.Context, tx *sql.Tx, scope Scope, id string) (enrollment.SoftwareIdentity, *x509.Certificate, *x509.Certificate, error) {
	var current enrollment.SoftwareIdentity
	if tx == nil || !scope.valid() || scope.SiteID <= 0 || !enrollment.ValidDeviceID(id) {
		return current, nil, nil, ErrDenied
	}
	var raw, root []byte
	err := tx.QueryRowContext(ctx, `SELECT i.id,i.tenant_id,i.site_id,i.certificate_hash,i.certificate,i.authority_certificate FROM uem_agent_identities i JOIN sites s ON s.id=i.site_id AND s.tenant_sites=i.tenant_id WHERE i.id=$1 AND i.tenant_id=$2 AND i.site_id=$3 AND i.platform='windows' AND i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp() FOR UPDATE OF i FOR SHARE OF s`, id, scope.TenantID, scope.SiteID).Scan(&current.AgentID, &current.TenantID, &current.SiteID, &current.CertificateHash, &raw, &root)
	if err != nil {
		return current, nil, nil, ErrDenied
	}
	cert, err := softwareCertificate(raw)
	if err != nil {
		return current, nil, nil, err
	}
	authority, err := softwareCertificate(root)
	if err != nil {
		return current, nil, nil, err
	}
	now := time.Now()
	roots := x509.NewCertPool()
	roots.AddCert(authority)
	if !current.Valid() || cert.Subject.CommonName != id || cert.IsCA || digest(cert.Raw) != current.CertificateHash || cert.CheckSignatureFrom(authority) != nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return current, nil, nil, ErrDenied
	}
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return current, nil, nil, ErrDenied
	}
	if err = softwareIdentityCurrent(ctx, tx, current); err != nil {
		return current, nil, nil, err
	}
	return current, cert, authority, nil
}
func softwareIdentityCurrent(ctx context.Context, tx *sql.Tx, i enrollment.SoftwareIdentity) error {
	var active bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_identities WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND platform='windows' AND certificate_hash=$4 AND revoked_at IS NULL AND certificate_expires_at>clock_timestamp())`, i.AgentID, i.TenantID, i.SiteID, i.CertificateHash).Scan(&active)
	if err != nil {
		return err
	}
	if !active {
		return ErrDenied
	}
	return nil
}
func softwareRecipient(ctx context.Context, tx *sql.Tx, i enrollment.SoftwareIdentity) (*enrollment.SoftwareRecipient, error) {
	r := &enrollment.SoftwareRecipient{Identity: i}
	err := tx.QueryRowContext(ctx, `SELECT id,public_key FROM uem_agent_software_recipients WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND certificate_hash=$4`, i.AgentID, i.TenantID, i.SiteID, i.CertificateHash).Scan(&r.ID, &r.PublicKey)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !r.Valid() {
		return nil, ErrDenied
	}
	return r, nil
}
func (s *AccessStore) SoftwareRecipient(ctx context.Context, tx *sql.Tx, scope Scope, id string) (*enrollment.SoftwareRecipient, *x509.Certificate, error) {
	i, cert, _, err := s.SoftwareIdentity(ctx, tx, scope, id)
	if err != nil {
		return nil, nil, err
	}
	r, err := softwareRecipient(ctx, tx, i)
	return r, cert, err
}
