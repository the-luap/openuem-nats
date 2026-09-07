package registry

import (
	"context"
	"crypto/x509"
	"database/sql"
	"math"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
)

// AccessStore requires no CA key or encryption master key. Broker authorization,
// request workers and disconnect workers can use separate database permissions
// without obtaining enrollment signing authority.
type AccessStore struct{ db *sql.DB }

func NewAccessStore(db *sql.DB) (*AccessStore, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &AccessStore{db: db}, nil
}

type Identity struct {
	Scope
	ID                   string    `json:"id"`
	Platform             string    `json:"platform"`
	Architecture         string    `json:"architecture"`
	DisplayName          string    `json:"display_name"`
	CertificateExpiresAt time.Time `json:"certificate_expires_at"`
}

// AuthorizeDevice locks the identity until its proposed broker session is
// persisted. Revocation takes the same lock, so it either denies this grant or
// sees the session that must be disconnected. Site moves fail closed as well.
func (s *AccessStore) AuthorizeDevice(ctx context.Context, key string, session enrollment.BrokerSession) (*enrollment.BrokerIdentity, error) {
	now := time.Now()
	if !nkeys.IsValidPublicUserKey(key) || !nkeys.IsValidPublicServerKey(session.ServerID) || session.ClientID == 0 || session.ClientID > math.MaxInt64 || !session.ExpiresAt.After(now) || session.ExpiresAt.After(now.Add(enrollment.BrokerLease+time.Second)) {
		return nil, ErrDenied
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var identity enrollment.BrokerIdentity
	err = tx.QueryRowContext(ctx, `SELECT d.id,d.certificate_expires_at FROM uem_agent_identities d JOIN sites s ON s.id=d.site_id AND s.tenant_sites=d.tenant_id WHERE d.broker_key=$1 AND d.revoked_at IS NULL AND d.certificate_expires_at>clock_timestamp() FOR UPDATE OF d FOR SHARE OF s`, key).Scan(&identity.DeviceID, &identity.CertificateExpiresAt)
	if err != nil {
		return nil, ErrDenied
	}
	if !identity.CertificateExpiresAt.After(time.Now()) || !session.ExpiresAt.After(time.Now()) {
		return nil, ErrDenied
	}
	if identity.CertificateExpiresAt.Before(session.ExpiresAt) {
		session.ExpiresAt = identity.CertificateExpiresAt
	}
	// A connection ID must never be reassigned to another key by a duplicate
	// authorization message. The conflict branch only extends this same device.
	result, err := tx.ExecContext(ctx, `INSERT INTO uem_agent_broker_sessions(server_id,client_id,device_id,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(server_id,client_id) DO UPDATE SET expires_at=GREATEST(uem_agent_broker_sessions.expires_at,excluded.expires_at) WHERE uem_agent_broker_sessions.device_id=excluded.device_id AND uem_agent_broker_sessions.disconnect_at IS NULL`, session.ServerID, int64(session.ClientID), identity.DeviceID, session.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		return nil, ErrDenied
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &identity, nil
}

func (s *AccessStore) ActiveIdentity(ctx context.Context, id string) (*Identity, error) {
	if !enrollment.ValidDeviceID(id) {
		return nil, ErrDenied
	}
	var identity Identity
	err := s.db.QueryRowContext(ctx, `SELECT d.id,d.tenant_id,d.site_id,d.platform,d.architecture,d.display_name,d.certificate_expires_at FROM uem_agent_identities d JOIN sites s ON s.id=d.site_id AND s.tenant_sites=d.tenant_id WHERE d.id=$1 AND d.revoked_at IS NULL AND d.certificate_expires_at>clock_timestamp()`, id).Scan(&identity.ID, &identity.TenantID, &identity.SiteID, &identity.Platform, &identity.Architecture, &identity.DisplayName, &identity.CertificateExpiresAt)
	if err != nil {
		return nil, ErrDenied
	}
	return &identity, nil
}

// AuthenticateCertificate is for a listener that has already proven TLS private
// key possession, including a validated pinned gateway boundary. A copied DER
// certificate received in an untrusted header is not authentication.
func (s *AccessStore) AuthenticateCertificate(ctx context.Context, id string, certificate *x509.Certificate) (*Identity, error) {
	if certificate == nil || !enrollment.ValidDeviceID(id) || certificate.NotBefore.After(time.Now()) || !certificate.NotAfter.After(time.Now()) {
		return nil, ErrDenied
	}
	var matches bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_identities WHERE id=$1 AND certificate_hash=$2 AND revoked_at IS NULL AND certificate_expires_at>clock_timestamp())`, id, digest(certificate.Raw)).Scan(&matches)
	if err != nil || !matches {
		return nil, ErrDenied
	}
	return s.ActiveIdentity(ctx, id)
}

// PendingDisconnects leases a bounded batch for five seconds. Attempts remain
// eligible until expiry, even after a successful kick: this covers a revocation
// racing with the broker finishing authentication and transient broker failures.
func (s *AccessStore) PendingDisconnects(ctx context.Context, limit int) ([]enrollment.BrokerSession, error) {
	if limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, `WITH due AS (SELECT server_id,client_id FROM uem_agent_broker_sessions WHERE disconnect_at IS NOT NULL AND expires_at>clock_timestamp() AND (attempted_at IS NULL OR attempted_at<clock_timestamp()-INTERVAL '5 seconds') ORDER BY attempted_at NULLS FIRST,disconnect_at,server_id,client_id LIMIT $1 FOR UPDATE SKIP LOCKED) UPDATE uem_agent_broker_sessions s SET attempted_at=clock_timestamp() FROM due WHERE s.server_id=due.server_id AND s.client_id=due.client_id RETURNING s.server_id,s.client_id,s.expires_at`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := []enrollment.BrokerSession{}
	for rows.Next() {
		var session enrollment.BrokerSession
		if err = rows.Scan(&session.ServerID, &session.ClientID, &session.ExpiresAt); err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func (s *AccessStore) CleanExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM uem_agent_broker_sessions WHERE expires_at<=clock_timestamp()`)
	return err
}

func (s *Store) RevokeIdentity(ctx context.Context, scope Scope, id, actor string) error {
	if !scope.valid() || !enrollment.ValidDeviceID(id) {
		return ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var siteID int
	var revoked sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT site_id,revoked_at FROM uem_agent_identities WHERE id=$1 AND tenant_id=$2 AND ($3=0 OR site_id=$3) FOR UPDATE`, id, scope.TenantID, scope.SiteID).Scan(&siteID, &revoked)
	if err != nil {
		return notFound(err)
	}
	if !revoked.Valid {
		if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1`, id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_broker_sessions SET disconnect_at=clock_timestamp() WHERE device_id=$1 AND expires_at>clock_timestamp()`, id); err != nil {
			return err
		}
		if err = audit(ctx, tx, Scope{TenantID: scope.TenantID, SiteID: siteID}, actor, "agent.identity.revoke", id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RevokeInvitation prevents future claims and retries. Already-issued identities
// have a separate explicit revocation lifecycle and are not silently removed.
func (s *Store) RevokeInvitation(ctx context.Context, scope Scope, id, actor string) error {
	if !scope.valid() || !enrollment.ValidDeviceID(id) {
		return ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var siteID int
	var revoked sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT site_id,revoked_at FROM uem_agent_invitations WHERE id=$1 AND tenant_id=$2 AND ($3=0 OR site_id=$3) FOR UPDATE`, id, scope.TenantID, scope.SiteID).Scan(&siteID, &revoked)
	if err != nil {
		return notFound(err)
	}
	if !revoked.Valid {
		if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_invitations SET revoked_at=clock_timestamp() WHERE id=$1`, id); err != nil {
			return err
		}
		if err = audit(ctx, tx, Scope{TenantID: scope.TenantID, SiteID: siteID}, actor, "agent.invitation.revoke", id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
