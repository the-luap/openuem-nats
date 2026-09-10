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

type rotationReconciliation struct {
	Version         int       `json:"version"`
	TaskID          string    `json:"task_id"`
	DeviceID        string    `json:"device_id"`
	TenantID        int       `json:"tenant_id"`
	SiteID          int       `json:"site_id"`
	CertificateHash string    `json:"certificate_hash"`
	ReceiptHash     string    `json:"receipt_hash"`
	Actor           string    `json:"actor"`
	ReconciledAt    time.Time `json:"reconciled_at"`
}

func rotationReconciliationPurpose(device, task string) string {
	return "identity-renewal/rotation-reconciliation/v1/" + device + "/" + task
}

func (s *Store) openRotationReconciliation(encoded []byte, device, task string) (*rotationReconciliation, error) {
	if len(encoded) > 16<<10 {
		return nil, ErrUnavailable
	}
	plain, err := s.open(encoded, rotationReconciliationPurpose(device, task))
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(plain)
	var r rotationReconciliation
	if strictjson.Unmarshal(plain, &r) != nil || r.Version != 1 || r.TaskID != task || r.DeviceID != device || r.Actor == "" || len(r.Actor) > 255 || r.ReconciledAt.IsZero() {
		return nil, ErrUnavailable
	}
	return &r, nil
}

// AcknowledgeRotationReconciliationInTransaction is for the trusted console key
// processor, never an endpoint or routing worker. The caller must first retain
// returned recovery keys (or complete verified uncertainty resolution) and write
// its final state/audit in this SAME transaction. A worker receipt alone is not
// permission to call this method. Keep the native-device then agent lock order,
// roll back on every error, and commit before reporting reconciliation success.
// The expected receipt hash must come from that caller's processed signed result.
func (s *Store) AcknowledgeRotationReconciliationInTransaction(ctx context.Context, tx *sql.Tx, scope Scope, device, task, receiptHash, actor string) error {
	if s == nil || tx == nil || !scope.valid() || scope.SiteID <= 0 || !enrollment.ValidDeviceID(device) || !enrollment.ValidDeviceID(task) || actor == "" || len(actor) > 255 || len(receiptHash) != 64 {
		return ErrDenied
	}
	current, err := loadIdentityRenewalCurrent(ctx, tx, device)
	if err != nil {
		return err
	}
	now := s.identityRenewalTime()
	if current.source.TenantID != scope.TenantID || current.source.SiteID != scope.SiteID || current.source.Platform != "macos" || current.validate(now) != nil {
		return ErrDenied
	}
	var wire, bound []byte
	var hash, resolution string
	var completed time.Time
	err = tx.QueryRowContext(ctx, `SELECT result,context,certificate_hash,COALESCE(resolution_task_id::text,''),completed_at FROM uem_agent_rotation_tasks WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND status='completed' AND delivered_at IS NOT NULL AND completed_at IS NOT NULL AND octet_length(result) BETWEEN 1 AND $5 FOR UPDATE`, task, device, scope.TenantID, scope.SiteID, enrollment.MaxRecoveryMessage).Scan(&wire, &bound, &hash, &resolution, &completed)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrDenied
	}
	if err != nil {
		return err
	}
	if hash != current.hash || receiptHash != digest(wire) || len(bound) > 4096 {
		return ErrDenied
	}
	var receipt enrollment.RotationResult
	if strictjson.Unmarshal(wire, &receipt) != nil {
		return ErrDenied
	}
	canonical, _ := json.Marshal(receipt)
	contextWire, _ := json.Marshal(receipt.Context)
	b := receipt.Context.Binding
	cert, err := x509.ParseCertificate(current.source.Certificate)
	if err != nil || !bytes.Equal(canonical, wire) || !bytes.Equal(contextWire, bound) || b.TaskID != task || b.Identity.AgentID != device || b.Identity.TenantID != scope.TenantID || b.Identity.SiteID != scope.SiteID || b.Identity.CertificateHash != hash || enrollment.VerifyRotationResult(receipt, cert, now) != nil || (receipt.Outcome == "uncertain" && (!receipt.ExecutionStopped || resolution == "")) {
		return ErrDenied
	}
	var previous []byte
	err = tx.QueryRowContext(ctx, `SELECT encrypted_record FROM uem_agent_rotation_reconciliations WHERE task_id=$1 AND device_id=$2`, task, device).Scan(&previous)
	if err == nil {
		r, err := s.openRotationReconciliation(previous, device, task)
		if err != nil || r.TenantID != scope.TenantID || r.SiteID != scope.SiteID || r.CertificateHash != hash || r.ReceiptHash != receiptHash || r.ReconciledAt.Before(completed) {
			return ErrUnavailable
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// Database completion and application clock may differ slightly. Use a fresh
	// database timestamp for the durable ordering of the acknowledgement.
	var at time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return err
	}
	if at.Before(completed) {
		return ErrDenied
	}
	r := rotationReconciliation{Version: 1, TaskID: task, DeviceID: device, TenantID: scope.TenantID, SiteID: scope.SiteID, CertificateHash: hash, ReceiptHash: receiptHash, Actor: actor, ReconciledAt: at}
	plain, err := json.Marshal(r)
	if err != nil {
		return ErrUnavailable
	}
	defer clear(plain)
	encoded, err := s.seal(plain, rotationReconciliationPurpose(device, task))
	if err != nil {
		return ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO uem_agent_rotation_reconciliations(task_id,device_id,encrypted_record) VALUES($1,$2,$3)`, task, device, encoded); err != nil {
		return err
	}
	return audit(ctx, tx, scope, actor, "recovery.rotation.reconciled", task)
}

// The identity lock serializes this scan with rotation delivery, receipts and
// trusted reconciliation. Completed receipts remain a blocker until the key
// processor's authenticated acknowledgement matches that exact immutable result.
func (s *Store) identityRenewalRotationGuard(ctx context.Context, tx *sql.Tx, current *identityRenewalCurrent) error {
	rows, err := tx.QueryContext(ctx, `SELECT t.id,t.tenant_id,t.site_id,t.certificate_hash,t.status,t.result,t.completed_at,r.encrypted_record FROM uem_agent_rotation_tasks t LEFT JOIN uem_agent_rotation_reconciliations r ON r.task_id=t.id AND r.device_id=t.device_id WHERE t.device_id=$1 AND (t.delivered_at IS NOT NULL OR t.status='uncertain') ORDER BY t.ordinal LIMIT $2`, current.source.DeviceID, enrollment.MaxRotationAttempts+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		var id, certificateHash, status string
		var tenant, site int
		var wire, encoded []byte
		var completed sql.NullTime
		if err := rows.Scan(&id, &tenant, &site, &certificateHash, &status, &wire, &completed, &encoded); err != nil {
			return err
		}
		if count > enrollment.MaxRotationAttempts || tenant != current.source.TenantID || site != current.source.SiteID {
			return ErrUnavailable
		}
		if status != "completed" || !completed.Valid || len(wire) == 0 || len(encoded) == 0 {
			return ErrRenewalRecoveryPending
		}
		r, err := s.openRotationReconciliation(encoded, current.source.DeviceID, id)
		if err != nil || r.TenantID != tenant || r.SiteID != site || r.CertificateHash != certificateHash || r.ReceiptHash != digest(wire) || r.ReconciledAt.Before(completed.Time) {
			return ErrUnavailable
		}
	}
	return rows.Err()
}
