package registry

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

func (s *AccessStore) RecoveryReady(ctx context.Context) bool {
	var ready bool
	err := s.db.QueryRowContext(ctx, `SELECT to_regclass('uem_agent_recovery_recipients') IS NOT NULL AND to_regclass('uem_agent_recovery_challenges') IS NOT NULL AND to_regclass('uem_agent_recovery_tasks') IS NOT NULL`).Scan(&ready)
	return err == nil && ready
}

// lockRecoveryIdentity follows the identity/site lock order used by broker
// authorization and rechecks time after any lock wait. Detached metadata from
// an earlier request is not authority for a recipient or task operation.
func lockRecoveryIdentity(ctx context.Context, tx *sql.Tx, scope Scope, id string) (enrollment.RecoveryIdentity, *x509.Certificate, error) {
	var identity enrollment.RecoveryIdentity
	if !scope.valid() || scope.SiteID <= 0 || !enrollment.ValidDeviceID(id) {
		return identity, nil, ErrDenied
	}
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT i.id,i.tenant_id,i.site_id,i.certificate_hash,i.certificate FROM uem_agent_identities i JOIN sites s ON s.id=i.site_id AND s.tenant_sites=i.tenant_id WHERE i.id=$1 AND i.tenant_id=$2 AND i.site_id=$3 AND i.platform='macos' AND i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp() FOR UPDATE OF i FOR SHARE OF s`, id, scope.TenantID, scope.SiteID).Scan(&identity.AgentID, &identity.TenantID, &identity.SiteID, &identity.CertificateHash, &raw)
	if err != nil {
		return identity, nil, ErrDenied
	}
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT revoked_at IS NULL AND certificate_expires_at>clock_timestamp() FROM uem_agent_identities WHERE id=$1`, id).Scan(&active); err != nil || !active {
		return identity, nil, ErrDenied
	}
	if block, rest := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return identity, nil, ErrDenied
		}
		raw = block.Bytes
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil || digest(certificate.Raw) != identity.CertificateHash || !identity.Valid() {
		return identity, nil, ErrDenied
	}
	return identity, certificate, nil
}

func recoveryRecipient(ctx context.Context, tx *sql.Tx, identity enrollment.RecoveryIdentity) (*enrollment.RecoveryRecipient, error) {
	r := &enrollment.RecoveryRecipient{Identity: identity}
	err := tx.QueryRowContext(ctx, `SELECT id,public_key FROM uem_agent_recovery_recipients WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND certificate_hash=$4`, identity.AgentID, identity.TenantID, identity.SiteID, identity.CertificateHash).Scan(&r.ID, &r.PublicKey)
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

// RecoveryRecipient locks the active agent identity in the caller's transaction.
// Console callers lock their native device and canonical association first.
func (s *AccessStore) RecoveryRecipient(ctx context.Context, tx *sql.Tx, scope Scope, id string) (*enrollment.RecoveryRecipient, *x509.Certificate, error) {
	if tx == nil {
		return nil, nil, ErrDenied
	}
	i, cert, err := lockRecoveryIdentity(ctx, tx, scope, id)
	if err != nil {
		return nil, nil, err
	}
	r, err := recoveryRecipient(ctx, tx, i)
	return r, cert, err
}

// HandleRecovery accepts only an already broker-authenticated, subject-bound
// request. Its current identity, site ownership and signatures are rechecked
// transactionally; it does not trust a client-supplied certificate or scope.
func (s *AccessStore) HandleRecovery(ctx context.Context, identity Identity, request enrollment.RecoveryRequest) (*enrollment.RecoveryReply, error) {
	if identity.Platform != "macos" || request.AgentID != identity.ID {
		return nil, ErrDenied
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, ErrDenied
	}
	if _, err = enrollment.DecodeRecoveryRequest(data, time.Now()); err != nil {
		return nil, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	i, cert, err := lockRecoveryIdentity(ctx, tx, identity.Scope, identity.ID)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_recovery_tasks SET status='expired',envelope='\x',completed_at=clock_timestamp() WHERE device_id=$1 AND status='pending' AND expires_at<=clock_timestamp()`, i.AgentID); err != nil {
		return nil, err
	}
	reply := &enrollment.RecoveryReply{Version: enrollment.RecoveryVersion, OK: true}
	switch request.Action {
	case "challenge":
		r, err := recoveryRecipient(ctx, tx, i)
		if err == nil && bytes.Equal(r.PublicKey, request.PublicKey) {
			reply.Recipient = r
			break
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		challenge := &enrollment.RecoveryRegistration{Version: enrollment.RecoveryVersion, Identity: i}
		var expires, created time.Time
		err = tx.QueryRowContext(ctx, `SELECT id,public_key,nonce,expires_at,created_at FROM uem_agent_recovery_challenges WHERE device_id=$1 AND certificate_hash=$2 AND consumed_at IS NULL`, i.AgentID, i.CertificateHash).Scan(&challenge.ID, &challenge.PublicKey, &challenge.Nonce, &expires, &created)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if err == nil && bytes.Equal(challenge.PublicKey, request.PublicKey) && expires.After(time.Now()) {
			challenge.ExpiresAt = expires.Unix()
			reply.Registration = challenge
			break
		}
		if err == nil && created.After(time.Now().Add(-5*time.Second)) {
			return nil, ErrDenied
		}
		expires = time.Now().Add(5 * time.Minute).Truncate(time.Second)
		if cert.NotAfter.Before(expires) {
			expires = cert.NotAfter
		}
		challenge.ID = uuid.NewString()
		challenge.PublicKey = bytes.Clone(request.PublicKey)
		challenge.Nonce = make([]byte, 32)
		challenge.ExpiresAt = expires.Unix()
		if _, err = rand.Read(challenge.Nonce); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_recovery_challenges(device_id,id,certificate_hash,public_key,nonce,expires_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(device_id) DO UPDATE SET id=EXCLUDED.id,certificate_hash=EXCLUDED.certificate_hash,public_key=EXCLUDED.public_key,nonce=EXCLUDED.nonce,expires_at=EXCLUDED.expires_at,created_at=clock_timestamp(),consumed_at=NULL`, i.AgentID, challenge.ID, i.CertificateHash, challenge.PublicKey, challenge.Nonce, expires); err != nil {
			return nil, err
		}
		reply.Registration = challenge
	case "register":
		c := request.Registration
		if c == nil || c.Identity != i || enrollment.VerifyRecoveryRegistration(*c, request.Signature, cert, time.Now()) != nil {
			return nil, ErrDenied
		}
		current, err := recoveryRecipient(ctx, tx, i)
		if err == nil && current.ID == c.ID && bytes.Equal(current.PublicKey, c.PublicKey) {
			reply.Recipient = current
			break
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		var matches bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_recovery_challenges WHERE device_id=$1 AND id=$2 AND certificate_hash=$3 AND public_key=$4 AND nonce=$5 AND expires_at=to_timestamp($6) AND expires_at>clock_timestamp() AND consumed_at IS NULL)`, i.AgentID, c.ID, i.CertificateHash, c.PublicKey, c.Nonce, c.ExpiresAt).Scan(&matches); err != nil || !matches {
			return nil, ErrDenied
		}
		if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_recovery_tasks SET status='cancelled',envelope='\x',completed_at=clock_timestamp() WHERE device_id=$1 AND status='pending'`, i.AgentID); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_recovery_recipients(device_id,tenant_id,site_id,id,certificate_hash,public_key) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(device_id) DO UPDATE SET id=EXCLUDED.id,certificate_hash=EXCLUDED.certificate_hash,public_key=EXCLUDED.public_key,registered_at=clock_timestamp()`, i.AgentID, i.TenantID, i.SiteID, c.ID, i.CertificateHash, c.PublicKey); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_recovery_challenges SET consumed_at=clock_timestamp() WHERE device_id=$1`, i.AgentID); err != nil {
			return nil, err
		}
		if err = audit(ctx, tx, identity.Scope, "device:"+i.AgentID, "recovery.recipient.registered", c.ID); err != nil {
			return nil, err
		}
		reply.Recipient = &enrollment.RecoveryRecipient{ID: c.ID, Identity: i, PublicKey: bytes.Clone(c.PublicKey)}
	case "poll":
		r, err := recoveryRecipient(ctx, tx, i)
		if err != nil || r.ID != request.RecipientID {
			return nil, ErrDenied
		}
		var envelope []byte
		var id string
		err = tx.QueryRowContext(ctx, `SELECT id,envelope FROM uem_agent_recovery_tasks WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND certificate_hash=$4 AND recipient_id=$5 AND status='pending' AND expires_at>clock_timestamp() ORDER BY created_at,id LIMIT 1 FOR UPDATE`, i.AgentID, i.TenantID, i.SiteID, i.CertificateHash, r.ID).Scan(&id, &envelope)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return nil, err
		}
		var task enrollment.RecoveryTask
		if json.Unmarshal(envelope, &task) != nil || !task.Valid(time.Now()) || task.Context.Identity != i || task.Context.RecipientID != r.ID || task.Context.TaskID != id {
			return nil, ErrDenied
		}
		if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_recovery_tasks SET delivered_at=clock_timestamp() WHERE id=$1`, id); err != nil {
			return nil, err
		}
		reply.Task = &task
	case "result":
		result := request.Result
		if result == nil || result.Context.Identity != i || enrollment.VerifyRecoveryResult(*result, cert, time.Now()) != nil {
			return nil, ErrDenied
		}
		r, err := recoveryRecipient(ctx, tx, i)
		if err != nil || r.ID != result.Context.RecipientID {
			return nil, ErrDenied
		}
		var status, nonceHash, native, key string
		var expires time.Time
		var delivered *time.Time
		var previous []byte
		c := result.Context
		err = tx.QueryRowContext(ctx, `SELECT status,nonce_hash,native_id,key_id,expires_at,delivered_at,result FROM uem_agent_recovery_tasks WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND recipient_id=$5 AND certificate_hash=$6 FOR UPDATE`, c.TaskID, i.AgentID, i.TenantID, i.SiteID, c.RecipientID, i.CertificateHash).Scan(&status, &nonceHash, &native, &key, &expires, &delivered, &previous)
		if err != nil || native != c.NativeID || key != c.KeyID || expires.Unix() != c.ExpiresAt || !expires.After(time.Now()) || delivered == nil || subtle.ConstantTimeCompare([]byte(nonceHash), []byte(digest(result.Nonce))) != 1 {
			return nil, ErrDenied
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return nil, ErrDenied
		}
		if status == "completed" && bytes.Equal(previous, encoded) {
			break
		}
		if status != "pending" {
			return nil, ErrDenied
		}
		if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_recovery_tasks SET status='completed',envelope='\x',result=$2,completed_at=clock_timestamp() WHERE id=$1`, c.TaskID, encoded); err != nil {
			return nil, err
		}
		if err = audit(ctx, tx, identity.Scope, "device:"+i.AgentID, "recovery.validation.reported", c.TaskID); err != nil {
			return nil, err
		}
	default:
		return nil, ErrDenied
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return reply, nil
}

// QueueRecoveryTask must be called inside the console's authorization and
// canonical Mac transaction. It records only HPKE ciphertext and a nonce hash.
func (s *AccessStore) QueueRecoveryTask(ctx context.Context, tx *sql.Tx, task enrollment.RecoveryTask, nonceHash string) error {
	c := task.Context
	if tx == nil || !task.Valid(time.Now()) || len(nonceHash) != 64 {
		return ErrDenied
	}
	i, cert, err := lockRecoveryIdentity(ctx, tx, Scope{TenantID: c.Identity.TenantID, SiteID: c.Identity.SiteID}, c.Identity.AgentID)
	if err != nil || i != c.Identity || time.Unix(c.ExpiresAt, 0).After(cert.NotAfter) {
		return ErrDenied
	}
	r, err := recoveryRecipient(ctx, tx, i)
	if err != nil || r.ID != c.RecipientID {
		return ErrDenied
	}
	envelope, err := json.Marshal(task)
	if err != nil || len(envelope) > enrollment.MaxRecoveryMessage {
		return ErrDenied
	}
	if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_recovery_tasks SET status='cancelled',envelope='\x',completed_at=clock_timestamp() WHERE device_id=$1 AND status='pending'`, i.AgentID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_recovery_tasks(id,tenant_id,site_id,device_id,native_id,key_id,recipient_id,certificate_hash,nonce_hash,envelope,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,to_timestamp($11))`, c.TaskID, i.TenantID, i.SiteID, i.AgentID, c.NativeID, c.KeyID, c.RecipientID, i.CertificateHash, nonceHash, envelope, c.ExpiresAt)
	return err
}

// ExpireRecoveryTasks erases up to 256 pending envelopes per maintenance pass,
// including offline devices. SKIP LOCKED avoids waiting on active requests.
func (s *AccessStore) ExpireRecoveryTasks(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `WITH stale AS (
 SELECT t.id FROM uem_agent_recovery_tasks t WHERE t.status='pending' AND
 (t.expires_at<=clock_timestamp() OR NOT EXISTS(
  SELECT 1 FROM uem_agent_identities i JOIN sites s ON s.id=i.site_id AND s.tenant_sites=i.tenant_id
  JOIN uem_agent_recovery_recipients r ON r.device_id=i.id AND r.id=t.recipient_id
   AND r.tenant_id=i.tenant_id AND r.site_id=i.site_id AND r.certificate_hash=i.certificate_hash
  WHERE i.id=t.device_id AND i.tenant_id=t.tenant_id AND i.site_id=t.site_id
   AND i.certificate_hash=t.certificate_hash AND i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp()))
 ORDER BY t.expires_at,t.id LIMIT 256 FOR UPDATE OF t SKIP LOCKED
) UPDATE uem_agent_recovery_tasks t SET status=CASE WHEN t.expires_at<=clock_timestamp() THEN 'expired' ELSE 'cancelled' END,
 envelope='\x',completed_at=clock_timestamp() FROM stale WHERE t.id=stale.id`)
	return err
}
