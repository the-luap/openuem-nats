package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-uem/nats/enrollment"
)

// SoftwareTaskStatus is a verified administrative projection. It deliberately
// excludes the encrypted envelope, nonce, private plan and certificate material.
// Reported means a receipt was accepted; only Outcome describes observed state.
type SoftwareTaskStatus struct {
	ID, PreparationID, RevisionID, AgentID, Operation, Actor, Status string
	Scope                                                            Scope
	CreatedAt, ExpiresAt                                             time.Time
	DeliveredAt, CompletedAt                                         *time.Time
	Outcome                                                          *enrollment.SoftwareOutcome
}

// ReadSoftwareTaskInTransaction requires the caller's read authorization and
// read audit in the same transaction. Historical scope remains authoritative
// after revocation or inventory moves; this method does not admit new work.
func (s *AccessStore) ReadSoftwareTaskInTransaction(ctx context.Context, tx *sql.Tx, scope Scope, id string) (*SoftwareTaskStatus, error) {
	if tx == nil || !scope.valid() || scope.SiteID <= 0 || !enrollment.ValidDeviceID(id) {
		return nil, ErrDenied
	}
	record, err := loadSoftwareTask(ctx, tx, scope, id)
	if err != nil {
		return nil, err
	}
	defer clear(record.result)
	c := record.task.Context
	status := &SoftwareTaskStatus{ID: id, PreparationID: c.PreparationID, RevisionID: c.RevisionID, AgentID: c.Identity.AgentID, Operation: c.Expectation.Operation, Actor: record.actor, Scope: scope, Status: record.status, CreatedAt: time.Unix(c.CreatedAt, 0).UTC(), ExpiresAt: time.Unix(c.ExpiresAt, 0).UTC(), DeliveredAt: record.deliveredAt}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT completed_at,clock_timestamp() FROM uem_agent_software_tasks WHERE id=$1 AND tenant_id=$2 AND site_id=$3`, id, scope.TenantID, scope.SiteID).Scan(&status.CompletedAt, &now); err != nil {
		return nil, err
	}
	if !status.ExpiresAt.After(now) {
		if status.Status == "pending" {
			status.Status = "expired"
		}
		if status.Status == "delivered" {
			status.Status = "uncertain"
		}
	}
	if len(record.result) > 0 {
		var result enrollment.SoftwareResult
		if json.Unmarshal(record.result, &result) != nil {
			return nil, ErrDenied
		}
		defer clear(result.Nonce)
		outcome := result.Outcome
		status.Outcome = &outcome
	}
	return status, nil
}

// CancelSoftwareTaskInTransaction requires fresh assignment rights in the
// original scope. Identity-before-task locking serializes cancellation with
// delivery. A delivered, uncertain or restart-required task cannot be cancelled
// by this API: only the endpoint can establish whether execution happened.
func (s *AccessStore) CancelSoftwareTaskInTransaction(ctx context.Context, tx *sql.Tx, scope Scope, id, actor string) (*SoftwareTaskStatus, error) {
	if tx == nil || !scope.valid() || scope.SiteID <= 0 || !enrollment.ValidDeviceID(id) || actor == "" {
		return nil, ErrDenied
	}
	var device string
	err := tx.QueryRowContext(ctx, `SELECT device_id FROM uem_agent_software_tasks WHERE id=$1 AND tenant_id=$2 AND site_id=$3`, id, scope.TenantID, scope.SiteID).Scan(&device)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var locked string
	// Revocation/expiry must not erase the original cancellation/history scope.
	err = tx.QueryRowContext(ctx, `SELECT id FROM uem_agent_identities WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR UPDATE`, device, scope.TenantID, scope.SiteID).Scan(&locked)
	if err != nil {
		return nil, ErrDenied
	}
	record, err := loadSoftwareTask(ctx, tx, scope, id)
	if err != nil {
		return nil, err
	}
	if record.status == "cancelled" || record.status == "expired" {
		return s.ReadSoftwareTaskInTransaction(ctx, tx, scope, id)
	}
	if record.status != "pending" || record.deliveredAt != nil || len(record.result) > 0 {
		return nil, ErrDenied
	}
	var status string
	err = tx.QueryRowContext(ctx, `UPDATE uem_agent_software_tasks SET status=CASE WHEN expires_at<=clock_timestamp() THEN 'expired' ELSE 'cancelled' END,completed_at=clock_timestamp() WHERE id=$1 AND status='pending' AND delivered_at IS NULL AND result IS NULL RETURNING status`, id).Scan(&status)
	if err != nil {
		return nil, ErrDenied
	}
	if err = audit(ctx, tx, scope, actor, "software.task."+status, id); err != nil {
		return nil, err
	}
	return s.ReadSoftwareTaskInTransaction(ctx, tx, scope, id)
}
