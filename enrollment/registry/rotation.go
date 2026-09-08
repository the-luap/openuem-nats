package registry

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-uem/nats/enrollment"
)

func (s *AccessStore) RotationReady(ctx context.Context) bool {
	var ready bool
	err := s.db.QueryRowContext(ctx, `SELECT to_regclass('uem_agent_rotation_tasks') IS NOT NULL`).Scan(&ready)
	return err == nil && ready && s.RecoveryReady(ctx)
}

func expireRotationForAgent(ctx context.Context, tx *sql.Tx, id string) error {
	_, err := tx.ExecContext(ctx, `UPDATE uem_agent_rotation_tasks SET status=CASE WHEN delivered_at IS NULL THEN 'expired' ELSE 'uncertain' END,envelope='\x',completed_at=CASE WHEN delivered_at IS NULL THEN clock_timestamp() ELSE NULL END WHERE device_id=$1 AND status='pending' AND expires_at<=clock_timestamp()`, id)
	return err
}

func rotationIdentity(ctx context.Context, tx *sql.Tx, scope Scope, id string) (enrollment.RecoveryIdentity, *x509.Certificate, error) {
	i, cert, err := lockRecoveryIdentity(ctx, tx, scope, id)
	if err != nil || cert == nil || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return i, nil, ErrDenied
	}
	return i, cert, nil
}

// NextRotationOrdinal allocates no state. The caller retains the identity row
// lock through encryption and QueueRotationTask in the same transaction. Slots
// are never reused, including after a failed or cancelled attempt.
func (s *AccessStore) NextRotationOrdinal(ctx context.Context, tx *sql.Tx, scope Scope, id string) (int, error) {
	if tx == nil {
		return 0, ErrDenied
	}
	if _, _, err := rotationIdentity(ctx, tx, scope, id); err != nil {
		return 0, err
	}
	if err := expireRotationForAgent(ctx, tx, id); err != nil {
		return 0, err
	}
	var ordinal int
	var pending bool
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(max(ordinal),0)+1,COALESCE(bool_or(status IN ('pending','uncertain')),false) FROM uem_agent_rotation_tasks WHERE device_id=$1`, id).Scan(&ordinal, &pending); err != nil {
		return 0, err
	}
	if pending || ordinal > enrollment.MaxRotationAttempts {
		return 0, ErrDenied
	}
	return ordinal, nil
}

// QueueRotationTask accepts only the console's authorized canonical-Mac
// transaction. Its context, encrypted envelope and nonce hash are immutable.
// The registry stores neither the old/new PRK nor the console reply private key.
func (s *AccessStore) QueueRotationTask(ctx context.Context, tx *sql.Tx, task enrollment.RotationTask, nonceHash string) error {
	c, b := task.Context, task.Context.Binding
	hash, err := hex.DecodeString(nonceHash)
	if tx == nil || !task.Valid(time.Now()) || err != nil || len(hash) != 32 || hex.EncodeToString(hash) != nonceHash {
		return ErrDenied
	}
	ordinal, err := s.NextRotationOrdinal(ctx, tx, Scope{TenantID: b.Identity.TenantID, SiteID: b.Identity.SiteID}, b.Identity.AgentID)
	if err != nil || ordinal != c.Ordinal {
		return ErrDenied
	}
	i, cert, err := rotationIdentity(ctx, tx, Scope{TenantID: b.Identity.TenantID, SiteID: b.Identity.SiteID}, b.Identity.AgentID)
	if err != nil || i != b.Identity || time.Unix(b.ExpiresAt, 0).Add(enrollment.RotationReceiptGrace).After(cert.NotAfter) {
		return ErrDenied
	}
	r, err := recoveryRecipient(ctx, tx, i)
	if err != nil || r.ID != b.RecipientID || hex.EncodeToString(r.PublicKey) == c.ReplyKey {
		return ErrDenied
	}
	envelope, err := json.Marshal(task)
	if err != nil || len(envelope) > enrollment.MaxRecoveryMessage {
		return ErrDenied
	}
	bound, err := json.Marshal(c)
	if err != nil {
		return ErrDenied
	}
	var withinLifetime bool
	if err = tx.QueryRowContext(ctx, `SELECT certificate_expires_at>=to_timestamp($2) AND certificate_expires_at>clock_timestamp() FROM uem_agent_identities WHERE id=$1`, i.AgentID, b.ExpiresAt+int64(enrollment.RotationReceiptGrace/time.Second)).Scan(&withinLifetime); err != nil || !withinLifetime || !task.Valid(time.Now()) {
		return ErrDenied
	}
	if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_recovery_tasks SET status='cancelled',envelope='\x',completed_at=clock_timestamp() WHERE device_id=$1 AND status='pending'`, i.AgentID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_rotation_tasks(id,tenant_id,site_id,device_id,ordinal,native_id,key_id,recipient_id,certificate_hash,nonce_hash,context,envelope,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,to_timestamp($13))`, b.TaskID, i.TenantID, i.SiteID, i.AgentID, c.Ordinal, b.NativeID, b.KeyID, b.RecipientID, i.CertificateHash, nonceHash, bound, envelope, b.ExpiresAt)
	return err
}

// HandleRotation requires the same broker subject/identity binding as recovery
// registration. A late signed receipt is useful even after its mutation deadline;
// it is accepted only for a task delivered under this exact current identity.
func (s *AccessStore) HandleRotation(ctx context.Context, identity Identity, request enrollment.RotationRequest) (*enrollment.RotationReply, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	reply, err := s.HandleRotationInTransaction(ctx, tx, identity, request)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return reply, nil
}

// HandleRotationInTransaction retains task/identity locks in the caller's
// transaction. Workers use this to hold their inventory scope authorization
// through the same delivery/result commit. The caller must roll back on error
// and commit successfully before returning any reply to the endpoint.
func (s *AccessStore) HandleRotationInTransaction(ctx context.Context, tx *sql.Tx, identity Identity, request enrollment.RotationRequest) (*enrollment.RotationReply, error) {
	if tx == nil {
		return nil, ErrDenied
	}
	if identity.Platform != "macos" || request.AgentID != identity.ID {
		return nil, ErrDenied
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, ErrDenied
	}
	if _, err = enrollment.DecodeRotationRequest(data); err != nil {
		return nil, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, cert, err := rotationIdentity(ctx, tx, identity.Scope, identity.ID)
	if err != nil {
		return nil, err
	}
	r, err := recoveryRecipient(ctx, tx, i)
	if err != nil {
		return nil, ErrDenied
	}
	if err = expireRotationForAgent(ctx, tx, i.AgentID); err != nil {
		return nil, err
	}
	reply := &enrollment.RotationReply{Version: enrollment.RotationVersion, Protocol: enrollment.RotationProtocol, OK: true}
	switch request.Action {
	case "poll":
		if request.RecipientID != r.ID {
			return nil, ErrDenied
		}
		var id, status string
		var envelope, bound []byte
		err = tx.QueryRowContext(ctx, `SELECT id,status,context,envelope FROM uem_agent_rotation_tasks WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND certificate_hash=$4 AND recipient_id=$5 AND status IN ('pending','uncertain') ORDER BY ordinal LIMIT 1 FOR UPDATE`, i.AgentID, i.TenantID, i.SiteID, i.CertificateHash, r.ID).Scan(&id, &status, &bound, &envelope)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return nil, err
		}
		var active bool
		if err = tx.QueryRowContext(ctx, `SELECT certificate_expires_at>clock_timestamp() AND revoked_at IS NULL FROM uem_agent_identities WHERE id=$1`, i.AgentID).Scan(&active); err != nil || !active || !time.Now().Before(cert.NotAfter) {
			return nil, ErrDenied
		}
		var c enrollment.RotationContext
		if json.Unmarshal(bound, &c) != nil || !c.ValidReceipt() || c.Binding.Identity != i || c.Binding.RecipientID != r.ID || c.Binding.TaskID != id {
			return nil, ErrDenied
		}
		canonical, _ := json.Marshal(c)
		if !bytes.Equal(canonical, bound) {
			return nil, ErrDenied
		}
		if status == "uncertain" {
			reply.Receipt = &c
			break
		}
		var task enrollment.RotationTask
		if json.Unmarshal(envelope, &task) != nil || task.Context != c || !task.Valid(time.Now()) {
			return nil, ErrDenied
		}
		canonical, _ = json.Marshal(task)
		if !bytes.Equal(canonical, envelope) {
			return nil, ErrDenied
		}
		// Certificate metadata may have been shortened since queueing. A live
		// request still needs its publication reserve at the delivery boundary;
		// receipt-only recovery above deliberately requires no new execution.
		var reserved bool
		if err = tx.QueryRowContext(ctx, `SELECT certificate_expires_at>=to_timestamp($2) FROM uem_agent_identities WHERE id=$1`, i.AgentID, c.Binding.ExpiresAt+int64(enrollment.RotationReceiptGrace/time.Second)).Scan(&reserved); err != nil || !reserved || time.Unix(c.Binding.ExpiresAt, 0).Add(enrollment.RotationReceiptGrace).After(cert.NotAfter) {
			return nil, ErrDenied
		}
		delivery, err := tx.ExecContext(ctx, `UPDATE uem_agent_rotation_tasks SET delivered_at=COALESCE(delivered_at,clock_timestamp()) WHERE id=$1 AND expires_at>clock_timestamp()`, id)
		if err != nil {
			return nil, err
		}
		if count, err := delivery.RowsAffected(); err != nil || count != 1 {
			return nil, ErrDenied
		}
		reply.Task = &task
	case "result":
		result := request.Result
		if result == nil || result.Context.Binding.Identity != i || result.Context.Binding.RecipientID != r.ID {
			return nil, ErrDenied
		}
		c, b := result.Context, result.Context.Binding
		var status, nonceHash string
		var bound, previous []byte
		var delivered *time.Time
		var created, expires time.Time
		err = tx.QueryRowContext(ctx, `SELECT status,nonce_hash,context,result,created_at,expires_at,delivered_at FROM uem_agent_rotation_tasks WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND recipient_id=$5 AND certificate_hash=$6 AND native_id=$7 AND key_id=$8 AND ordinal=$9 FOR UPDATE`, b.TaskID, i.AgentID, i.TenantID, i.SiteID, b.RecipientID, i.CertificateHash, b.NativeID, b.KeyID, c.Ordinal).Scan(&status, &nonceHash, &bound, &previous, &created, &expires, &delivered)
		if err != nil {
			return nil, ErrDenied
		}
		canonical, _ := json.Marshal(c)
		if !bytes.Equal(canonical, bound) || expires.Unix() != b.ExpiresAt || delivered == nil || delivered.Before(created) || !delivered.Before(expires) || subtle.ConstantTimeCompare([]byte(nonceHash), []byte(digest(result.Nonce))) != 1 || enrollment.VerifyRotationResult(*result, cert, time.Now()) != nil {
			return nil, ErrDenied
		}
		var active bool
		if err = tx.QueryRowContext(ctx, `SELECT certificate_expires_at>clock_timestamp() AND revoked_at IS NULL FROM uem_agent_identities WHERE id=$1`, i.AgentID).Scan(&active); err != nil || !active {
			return nil, ErrDenied
		}
		encoded, err := json.Marshal(result)
		if err != nil || len(encoded) > enrollment.MaxRecoveryMessage {
			return nil, ErrDenied
		}
		if len(previous) > 0 {
			if (status == "completed" || status == "uncertain") && bytes.Equal(previous, encoded) {
				break
			}
			return nil, ErrDenied
		}
		if status != "pending" && status != "uncertain" {
			return nil, ErrDenied
		}
		// A signed uncertainty report is an immutable receipt, but it does not
		// resolve the mutation. Keep the slot active until the console proves
		// which key is current through its independent recovery workflow.
		if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_rotation_tasks SET status=CASE WHEN $3='uncertain' THEN 'uncertain' ELSE 'completed' END,envelope='\x',result=$2,completed_at=CASE WHEN $3='uncertain' THEN NULL ELSE clock_timestamp() END WHERE id=$1`, b.TaskID, encoded, result.Outcome); err != nil {
			return nil, err
		}
		if err = audit(ctx, tx, identity.Scope, "device:"+i.AgentID, "recovery.rotation.reported", b.TaskID); err != nil {
			return nil, err
		}
	default:
		return nil, ErrDenied
	}
	return reply, nil
}

// ExpireRotationTasks preserves delivered uncertainty and encrypted receipts.
// Stale authority cancels delivery; a clock deadline alone cannot prove whether
// the Mac changed its key. Work per maintenance pass is bounded.
func (s *AccessStore) ExpireRotationTasks(ctx context.Context) error {
	const authority = `EXISTS(SELECT 1 FROM uem_agent_identities i JOIN sites s ON s.id=i.site_id AND s.tenant_sites=i.tenant_id
  JOIN uem_agent_recovery_recipients r ON r.device_id=i.id AND r.id=t.recipient_id AND r.certificate_hash=i.certificate_hash AND r.tenant_id=i.tenant_id AND r.site_id=i.site_id
  WHERE i.id=t.device_id AND i.tenant_id=t.tenant_id AND i.site_id=t.site_id AND i.certificate_hash=t.certificate_hash AND i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp())`
	_, err := s.db.ExecContext(ctx, `WITH stale AS (
 SELECT t.id,NOT `+authority+` AS invalid
 FROM uem_agent_rotation_tasks t WHERE t.status IN ('pending','uncertain') AND ((t.status='pending' AND t.expires_at<=clock_timestamp()) OR NOT `+authority+`)
 ORDER BY t.expires_at,t.id LIMIT 256 FOR UPDATE OF t SKIP LOCKED
) UPDATE uem_agent_rotation_tasks t SET
 status=CASE WHEN stale.invalid THEN 'cancelled' WHEN t.delivered_at IS NULL THEN 'expired' ELSE 'uncertain' END,
 envelope='\x',completed_at=CASE WHEN stale.invalid OR t.delivered_at IS NULL THEN clock_timestamp() ELSE NULL END
 FROM stale WHERE t.id=stale.id AND (stale.invalid OR (t.status='pending' AND t.expires_at<=clock_timestamp()))`)
	return err
}
