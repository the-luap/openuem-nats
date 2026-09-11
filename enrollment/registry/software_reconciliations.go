package registry

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/open-uem/nats/enrollment"
)

type softwareReconciliationRecord struct {
	task                                         *enrollment.SoftwareReconciliationTask
	certificate                                  *x509.Certificate
	taskHash, actor, status, resultHash, outcome string
	result                                       *enrollment.SoftwareReconciliationResult
	resultWire                                   []byte
	deliveredAt, completedAt                     *time.Time
}

// Callers lock the identity, original software task, then reconciliation rows.
// The supplied original is already verified by loadSoftwareTask; passing it
// avoids recursive loads when checking an original task's release evidence.
func loadSoftwareReconciliation(ctx context.Context, tx *sql.Tx, scope Scope, id string, original *softwareTaskRecord) (*softwareReconciliationRecord, error) {
	if original == nil || original.task == nil {
		return nil, ErrDenied
	}
	var device, originalID, certificateHash string
	var certificate, envelope, contextWire []byte
	var created, expires time.Time
	var resultHash, outcome sql.NullString
	record := new(softwareReconciliationRecord)
	err := tx.QueryRowContext(ctx, `SELECT device_id,original_task_id,certificate_hash,certificate,task_hash,task_context,envelope,actor,status,created_at,expires_at,delivered_at,result,result_hash,outcome,completed_at FROM uem_agent_software_reconciliations WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR UPDATE`, id, scope.TenantID, scope.SiteID).Scan(&device, &originalID, &certificateHash, &certificate, &record.taskHash, &contextWire, &envelope, &record.actor, &record.status, &created, &expires, &record.deliveredAt, &record.resultWire, &resultHash, &outcome, &record.completedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	record.task, err = enrollment.DecodeSoftwareReconciliationTask(envelope)
	if err != nil {
		return nil, ErrDenied
	}
	c := record.task.Context
	canonical, err := json.Marshal(c)
	if err != nil || !bytes.Equal(canonical, contextWire) || c.ID != id || c.Identity.AgentID != device || c.Identity.TenantID != scope.TenantID || c.Identity.SiteID != scope.SiteID || c.Identity.CertificateHash != certificateHash || c.Original.TaskID != originalID || !c.Original.Equal(original.task.Context) || c.OriginalTaskHash != original.taskHash || c.CreatedAt != created.Unix() || c.ExpiresAt != expires.Unix() || enrollment.VerifySoftwareReconciliationTaskHistory(*record.task, original.authority) != nil {
		return nil, ErrDenied
	}
	hash, err := record.task.Digest()
	if err != nil || hash != record.taskHash {
		return nil, ErrDenied
	}
	record.certificate, err = softwareCertificate(certificate)
	if err != nil || record.certificate.IsCA || record.certificate.Subject.CommonName != device || digest(record.certificate.Raw) != certificateHash || record.certificate.CheckSignatureFrom(original.authority) != nil || c.ExpiresAt > record.certificate.NotAfter.Unix() {
		return nil, ErrDenied
	}
	roots := x509.NewCertPool()
	roots.AddCert(original.authority)
	if _, err := record.certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Unix(c.CreatedAt, 0), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, ErrDenied
	}
	if len(record.resultWire) > 0 {
		record.result, err = enrollment.DecodeSoftwareReconciliationResult(record.resultWire, time.Now())
		if err != nil || record.status != "reported" || record.deliveredAt == nil || record.completedAt == nil || !resultHash.Valid || !outcome.Valid || enrollment.VerifySoftwareReconciliationEvidence(*record.task, *original.task, *record.result, original.authority, original.nonceHash, time.Now()) != nil || !bytes.Equal(record.result.Certificate, record.certificate.Raw) || record.result.Outcome.State != outcome.String {
			return nil, ErrDenied
		}
		receipt, err := enrollment.SoftwareReconciliationReceipt(*record.result, time.Now())
		if err != nil || receipt.ResultHash != resultHash.String {
			return nil, ErrDenied
		}
		record.resultHash, record.outcome = resultHash.String, outcome.String
	} else if resultHash.Valid || outcome.Valid || record.status == "reported" {
		return nil, ErrDenied
	}
	return record, nil
}

func verifySoftwareRelease(ctx context.Context, tx *sql.Tx, scope Scope, original *softwareTaskRecord) error {
	if original.reconciliationID == "" {
		if original.reconciledAt != nil {
			return ErrDenied
		}
		return nil
	}
	if original.reconciledAt == nil || original.deliveredAt == nil {
		return ErrDenied
	}
	record, err := loadSoftwareReconciliation(ctx, tx, scope, original.reconciliationID, original)
	if err != nil || record.result == nil || record.completedAt == nil || !record.completedAt.Equal(*original.reconciledAt) || !record.result.Outcome.AllowsRelease(original.task.Context.Expectation) {
		return ErrDenied
	}
	return nil
}

// QueueSoftwareReconciliationInTransaction requires the caller's explicit
// current assignment permission and current Windows inventory/capability locks.
// It never reissues the original executable plan or releases its reservation.
func (s *Store) QueueSoftwareReconciliationInTransaction(ctx context.Context, tx *sql.Tx, scope Scope, device, originalID, id string, expires time.Time, actor string) (*enrollment.SoftwareReconciliationTask, error) {
	if tx == nil || !scope.valid() || scope.SiteID <= 0 || actor == "" || !enrollment.ValidDeviceID(device) || !enrollment.ValidDeviceID(originalID) || !enrollment.ValidDeviceID(id) || originalID == id {
		return nil, ErrDenied
	}
	access, _ := NewAccessStore(s.db)
	identity, certificate, authority, err := access.SoftwareIdentity(ctx, tx, scope, device)
	if err != nil {
		return nil, err
	}
	if err := expireSoftwareForAgent(ctx, tx, device); err != nil {
		return nil, err
	}
	original, err := loadSoftwareTask(ctx, tx, scope, originalID)
	if err != nil {
		return nil, err
	}
	if original.task.Context.Identity.AgentID != device || !bytes.Equal(original.authority.Raw, authority.Raw) {
		return nil, ErrDenied
	}
	expires = expires.Truncate(time.Second)
	previous, err := loadSoftwareReconciliation(ctx, tx, scope, id, original)
	if err == nil {
		if previous.actor != actor || previous.task.Context.Identity != identity || previous.task.Context.ExpiresAt != expires.Unix() {
			return nil, ErrDenied
		}
		return previous.task, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if original.deliveredAt == nil || original.reconciliationID != "" || original.status != "uncertain" && original.status != "restart_required" {
		return nil, ErrDenied
	}
	if err := expireSoftwareReconciliations(ctx, tx, device); err != nil {
		return nil, err
	}
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_software_reconciliations WHERE original_task_id=$1 AND status IN ('pending','delivered'))`, originalID).Scan(&active); err != nil {
		return nil, err
	}
	if active {
		return nil, ErrDenied
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	now = now.Truncate(time.Second)
	if !expires.After(now.Add(time.Minute)) || expires.After(now.Add(time.Hour)) || expires.After(certificate.NotAfter) {
		return nil, ErrDenied
	}
	var authorityPEM, encrypted []byte
	if err = tx.QueryRowContext(ctx, `SELECT certificate,encrypted_key FROM uem_agent_authorities WHERE tenant_id=$1 FOR SHARE`, scope.TenantID).Scan(&authorityPEM, &encrypted); err != nil {
		return nil, err
	}
	private, err := s.open(encrypted, fmt.Sprintf("%d/authority/key", scope.TenantID))
	if err != nil {
		return nil, ErrDenied
	}
	defer clear(private)
	pinned, issuer, err := parseAuthority(authorityPEM, private)
	if err != nil || !bytes.Equal(pinned.Raw, authority.Raw) {
		return nil, ErrDenied
	}
	c := enrollment.SoftwareReconciliationContext{Version: enrollment.SoftwareReconciliationVersion, Protocol: enrollment.SoftwareReconciliationProtocol, Identity: identity, ID: id, Original: original.task.Context, OriginalTaskHash: original.taskHash, CreatedAt: now.Unix(), ExpiresAt: expires.Unix()}
	task, err := enrollment.SignSoftwareReconciliationTask(c, pinned, issuer, now)
	if err != nil {
		return nil, ErrDenied
	}
	envelope, err := json.Marshal(task)
	if err != nil || len(envelope) > enrollment.MaxSoftwareMessage {
		return nil, ErrDenied
	}
	contextWire, _ := json.Marshal(c)
	hash, err := task.Digest()
	if err != nil {
		return nil, ErrDenied
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_software_reconciliations(id,tenant_id,site_id,device_id,original_task_id,certificate_hash,certificate,task_hash,task_context,envelope,actor,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, id, scope.TenantID, scope.SiteID, device, originalID, identity.CertificateHash, certificate.Raw, hash, contextWire, envelope, actor, now, expires)
	if err != nil {
		return nil, err
	}
	if err := audit(ctx, tx, scope, actor, "software.reconciliation.queued", id); err != nil {
		return nil, err
	}
	if err := softwareIdentityCurrent(ctx, tx, identity); err != nil {
		return nil, err
	}
	if !expires.After(time.Now()) {
		return nil, ErrDenied
	}
	return task, nil
}

func expireSoftwareReconciliations(ctx context.Context, tx *sql.Tx, device string) error {
	rows, err := tx.QueryContext(ctx, `UPDATE uem_agent_software_reconciliations SET status='expired',completed_at=clock_timestamp() WHERE device_id=$1 AND status IN ('pending','delivered') AND expires_at<=clock_timestamp() RETURNING id,tenant_id,site_id`, device)
	if err != nil {
		return err
	}
	type expired struct {
		id    string
		scope Scope
	}
	var expiredRows []expired
	for rows.Next() {
		var row expired
		if err := rows.Scan(&row.id, &row.scope.TenantID, &row.scope.SiteID); err != nil {
			rows.Close()
			return err
		}
		expiredRows = append(expiredRows, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, row := range expiredRows {
		if err := audit(ctx, tx, row.scope, "system", "software.reconciliation.expired", row.id); err != nil {
			return err
		}
	}
	return nil
}
