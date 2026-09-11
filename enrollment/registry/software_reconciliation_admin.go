package registry

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/open-uem/nats/enrollment"
)

// This administrative projection excludes all nonce, certificate and envelope
// material. Original execution and later observation remain distinct evidence.
type SoftwareReconciliationStatus struct {
	ID, OriginalTaskID, AgentID, Actor, Status string
	Scope                                      Scope
	CreatedAt, ExpiresAt                       time.Time
	DeliveredAt, CompletedAt                   *time.Time
	Outcome                                    *enrollment.SoftwareReconciliationOutcome
	ReleasesReservation                        bool
}

func softwareReconciliationOriginal(ctx context.Context, tx *sql.Tx, scope Scope, id string) (string, string, error) {
	var original, device string
	err := tx.QueryRowContext(ctx, `SELECT original_task_id,device_id FROM uem_agent_software_reconciliations WHERE id=$1 AND tenant_id=$2 AND site_id=$3`, id, scope.TenantID, scope.SiteID).Scan(&original, &device)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return original, device, err
}

// The caller holds its original-scope read authorization and commits a read
// audit in this transaction, including when the device has since been revoked.
func (s *AccessStore) ReadSoftwareReconciliationInTransaction(ctx context.Context, tx *sql.Tx, scope Scope, id string) (*SoftwareReconciliationStatus, error) {
	if tx == nil || !scope.valid() || scope.SiteID <= 0 || !enrollment.ValidDeviceID(id) {
		return nil, ErrDenied
	}
	originalID, _, err := softwareReconciliationOriginal(ctx, tx, scope, id)
	if err != nil {
		return nil, err
	}
	original, err := loadSoftwareTask(ctx, tx, scope, originalID)
	if err != nil {
		return nil, err
	}
	record, err := loadSoftwareReconciliation(ctx, tx, scope, id, original)
	if err != nil {
		return nil, err
	}
	c := record.task.Context
	status := &SoftwareReconciliationStatus{ID: id, OriginalTaskID: originalID, AgentID: c.Identity.AgentID, Actor: record.actor, Status: record.status, Scope: scope, CreatedAt: time.Unix(c.CreatedAt, 0).UTC(), ExpiresAt: time.Unix(c.ExpiresAt, 0).UTC(), DeliveredAt: record.deliveredAt, CompletedAt: record.completedAt, ReleasesReservation: original.reconciliationID == id}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	if !status.ExpiresAt.After(now) && (status.Status == "pending" || status.Status == "delivered") {
		status.Status = "expired"
	}
	if record.result != nil {
		outcome := record.result.Outcome
		status.Outcome = &outcome
	}
	return status, nil
}

// Cancellation is an original-scope administrative operation, never a device
// RPC. It cannot remove accepted evidence or release the original reservation.
func (s *AccessStore) CancelSoftwareReconciliationInTransaction(ctx context.Context, tx *sql.Tx, scope Scope, id, actor string) (*SoftwareReconciliationStatus, error) {
	if tx == nil || !scope.valid() || scope.SiteID <= 0 || !enrollment.ValidDeviceID(id) || actor == "" {
		return nil, ErrDenied
	}
	originalID, device, err := softwareReconciliationOriginal(ctx, tx, scope, id)
	if err != nil {
		return nil, err
	}
	var locked string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM uem_agent_identities WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR UPDATE`, device, scope.TenantID, scope.SiteID).Scan(&locked); err != nil {
		return nil, ErrDenied
	}
	original, err := loadSoftwareTask(ctx, tx, scope, originalID)
	if err != nil {
		return nil, err
	}
	record, err := loadSoftwareReconciliation(ctx, tx, scope, id, original)
	if err != nil {
		return nil, err
	}
	if record.status == "cancelled" || record.status == "expired" {
		return s.ReadSoftwareReconciliationInTransaction(ctx, tx, scope, id)
	}
	if record.status != "pending" || record.deliveredAt != nil || record.result != nil {
		return nil, ErrDenied
	}
	var status string
	if err := tx.QueryRowContext(ctx, `UPDATE uem_agent_software_reconciliations SET status=CASE WHEN expires_at<=clock_timestamp() THEN 'expired' ELSE 'cancelled' END,completed_at=clock_timestamp() WHERE id=$1 AND status='pending' RETURNING status`, id).Scan(&status); err != nil {
		return nil, ErrDenied
	}
	if err := audit(ctx, tx, scope, actor, "software.reconciliation."+status, id); err != nil {
		return nil, err
	}
	return s.ReadSoftwareReconciliationInTransaction(ctx, tx, scope, id)
}
