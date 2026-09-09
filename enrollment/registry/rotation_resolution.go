package registry

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/open-uem/nats/enrollment"
)

// QueueRotationValidation admits only read-only validation after the endpoint's
// immutable signed uncertainty receipt explicitly proves execution stopped.
// An elapsed deadline without that receipt never admits this recovery path.
// The console must independently authorize the native Mac and current key in tx.
func (s *AccessStore) QueueRotationValidation(ctx context.Context, tx *sql.Tx, rotation enrollment.RotationContext, task enrollment.RecoveryTask, nonceHash string) error {
	return s.queueRecoveryTask(ctx, tx, task, nonceHash, &rotation)
}

func lockUncertainRotation(ctx context.Context, tx *sql.Tx, c enrollment.RotationContext, cert *x509.Certificate) (string, error) {
	if tx == nil || !c.ValidReceipt() || cert == nil {
		return "", ErrDenied
	}
	var status, nonceHash, proof string
	var bound, wire []byte
	var delivered *time.Time
	var created, expires time.Time
	err := tx.QueryRowContext(ctx, `SELECT status,nonce_hash,context,result,created_at,expires_at,delivered_at,COALESCE(resolution_task_id::text,'') FROM uem_agent_rotation_tasks WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND recipient_id=$5 AND certificate_hash=$6 AND native_id=$7 AND key_id=$8 AND ordinal=$9 FOR UPDATE`, c.Binding.TaskID, c.Binding.Identity.AgentID, c.Binding.Identity.TenantID, c.Binding.Identity.SiteID, c.Binding.RecipientID, c.Binding.Identity.CertificateHash, c.Binding.NativeID, c.Binding.KeyID, c.Ordinal).Scan(&status, &nonceHash, &bound, &wire, &created, &expires, &delivered, &proof)
	if err != nil {
		return "", ErrDenied
	}
	canonical, _ := json.Marshal(c)
	if status != "uncertain" || !bytes.Equal(canonical, bound) || expires.Unix() != c.Binding.ExpiresAt || delivered == nil || delivered.Before(created) || !delivered.Before(expires) || len(wire) > enrollment.MaxRecoveryMessage {
		return "", ErrDenied
	}
	var receipt enrollment.RotationResult
	if json.Unmarshal(wire, &receipt) != nil {
		return "", ErrDenied
	}
	canonical, _ = json.Marshal(receipt)
	if !bytes.Equal(canonical, wire) || receipt.Context != c || receipt.Outcome != "uncertain" || !receipt.ExecutionStopped || subtle.ConstantTimeCompare([]byte(digest(receipt.Nonce)), []byte(nonceHash)) != 1 || enrollment.VerifyRotationResult(receipt, cert, time.Now()) != nil {
		return "", ErrDenied
	}
	return proof, nil
}

// ResolveRotation retains the original signed uncertainty receipt and ordinal.
// Only the explicitly selected, subsequently delivered valid proof can unblock
// another attempt. The console must first independently verify this same proof
// and current native key/association in the caller-owned transaction.
func (s *AccessStore) ResolveRotation(ctx context.Context, tx *sql.Tx, c enrollment.RotationContext, proof enrollment.RecoveryContext, nonceHash, actor string) error {
	if tx == nil || !c.ValidReceipt() || actor == "" || len(actor) > 255 || c.Binding.Identity != proof.Identity || c.Binding.RecipientID != proof.RecipientID || c.Binding.NativeID != proof.NativeID {
		return ErrDenied
	}
	i, cert, err := rotationIdentity(ctx, tx, Scope{TenantID: c.Binding.Identity.TenantID, SiteID: c.Binding.Identity.SiteID}, c.Binding.Identity.AgentID)
	if err != nil || i != c.Binding.Identity {
		return ErrDenied
	}
	r, err := recoveryRecipient(ctx, tx, i)
	if err != nil || r.ID != c.Binding.RecipientID {
		return ErrDenied
	}
	selected, err := lockUncertainRotation(ctx, tx, c, cert)
	if err != nil || selected != proof.TaskID {
		return ErrDenied
	}
	var wire []byte
	var created, expires time.Time
	var delivered, completed *time.Time
	err = tx.QueryRowContext(ctx, `SELECT result,created_at,expires_at,delivered_at,completed_at FROM uem_agent_recovery_tasks WHERE id=$1 AND status='completed' AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND native_id=$5 AND key_id=$6 AND recipient_id=$7 AND certificate_hash=$8 AND nonce_hash=$9 FOR UPDATE`, proof.TaskID, i.AgentID, i.TenantID, i.SiteID, proof.NativeID, proof.KeyID, r.ID, i.CertificateHash, nonceHash).Scan(&wire, &created, &expires, &delivered, &completed)
	if err != nil || delivered == nil || completed == nil || delivered.Before(created) || completed.Before(*delivered) || !completed.Before(expires) || expires.Unix() != proof.ExpiresAt || completed.After(time.Now()) || len(wire) > enrollment.MaxRecoveryMessage {
		return ErrDenied
	}
	var receipt enrollment.RecoveryResult
	if json.Unmarshal(wire, &receipt) != nil {
		return ErrDenied
	}
	canonical, _ := json.Marshal(receipt)
	if !bytes.Equal(canonical, wire) || receipt.Context != proof || receipt.Outcome != "valid" || subtle.ConstantTimeCompare([]byte(digest(receipt.Nonce)), []byte(nonceHash)) != 1 || enrollment.VerifyRecoveryResult(receipt, cert, *completed) != nil {
		return ErrDenied
	}
	// Task locks can outlive a certificate or a shortened registry lifetime.
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT certificate_expires_at>clock_timestamp() AND revoked_at IS NULL FROM uem_agent_identities WHERE id=$1`, i.AgentID).Scan(&active); err != nil || !active || !time.Now().Before(cert.NotAfter) {
		return ErrDenied
	}
	if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_rotation_tasks SET status='completed',completed_at=clock_timestamp(),resolved_at=clock_timestamp() WHERE id=$1`, c.Binding.TaskID); err != nil {
		return err
	}
	return audit(ctx, tx, Scope{TenantID: i.TenantID, SiteID: i.SiteID}, actor, "recovery.rotation.resolved", c.Binding.TaskID)
}
