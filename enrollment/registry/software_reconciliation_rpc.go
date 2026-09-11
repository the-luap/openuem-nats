package registry

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-uem/nats/enrollment"
)

// HandleSoftwareReconciliationInTransaction requires an authenticated Windows
// subject and the caller's held current identity/inventory scope locks. No reply
// may leave the worker until this transaction and its audits have committed.
func (s *AccessStore) HandleSoftwareReconciliationInTransaction(ctx context.Context, tx *sql.Tx, identity Identity, request enrollment.SoftwareReconciliationRequest) (*enrollment.SoftwareReconciliationReply, error) {
	if tx == nil || identity.Platform != "windows" || request.AgentID != identity.ID {
		return nil, ErrDenied
	}
	data, err := json.Marshal(request)
	defer clear(data)
	if err != nil {
		return nil, ErrDenied
	}
	if _, err := enrollment.DecodeSoftwareReconciliationRequest(data, time.Now()); err != nil {
		return nil, ErrDenied
	}
	current, certificate, authority, err := s.SoftwareIdentity(ctx, tx, identity.Scope, identity.ID)
	if err != nil {
		return nil, err
	}
	if err := expireSoftwareForAgent(ctx, tx, identity.ID); err != nil {
		return nil, err
	}
	if err := expireSoftwareReconciliations(ctx, tx, identity.ID); err != nil {
		return nil, err
	}
	reply := &enrollment.SoftwareReconciliationReply{Version: enrollment.SoftwareReconciliationVersion, Protocol: enrollment.SoftwareReconciliationProtocol, OK: true}
	switch request.Action {
	case "poll":
		var id, originalID string
		err := tx.QueryRowContext(ctx, `SELECT r.id,r.original_task_id FROM uem_agent_software_reconciliations r JOIN uem_agent_software_tasks t ON t.id=r.original_task_id WHERE r.device_id=$1 AND r.tenant_id=$2 AND r.site_id=$3 AND r.certificate_hash=$4 AND r.status IN ('pending','delivered') AND r.expires_at>clock_timestamp() AND t.reconciliation_id IS NULL AND t.status IN ('uncertain','restart_required') ORDER BY r.created_at,r.id LIMIT 1`, identity.ID, identity.TenantID, identity.SiteID, current.CertificateHash).Scan(&id, &originalID)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return nil, err
		}
		original, err := loadSoftwareTask(ctx, tx, identity.Scope, originalID)
		if err != nil {
			return nil, err
		}
		record, err := loadSoftwareReconciliation(ctx, tx, identity.Scope, id, original)
		if err != nil || !bytes.Equal(original.authority.Raw, authority.Raw) || enrollment.VerifySoftwareReconciliationTask(*record.task, authority, current, time.Now()) != nil {
			return nil, ErrDenied
		}
		if record.status == "pending" {
			if _, err := tx.ExecContext(ctx, `UPDATE uem_agent_software_reconciliations SET status='delivered',delivered_at=clock_timestamp() WHERE id=$1 AND status='pending'`, id); err != nil {
				return nil, err
			}
			if err := audit(ctx, tx, identity.Scope, "device:"+identity.ID, "software.reconciliation.delivered", id); err != nil {
				return nil, err
			}
		}
		reply.Task = record.task
	case "result":
		result := request.Result
		if enrollment.VerifySoftwareReconciliationSubmission(*request.Submission, *result, current, certificate, time.Now()) != nil {
			return nil, ErrDenied
		}
		original, err := loadSoftwareTask(ctx, tx, identity.Scope, result.Context.Original.TaskID)
		if err != nil {
			return nil, err
		}
		record, err := loadSoftwareReconciliation(ctx, tx, identity.Scope, result.Context.ID, original)
		if err != nil || record.deliveredAt == nil || !bytes.Equal(original.authority.Raw, authority.Raw) || enrollment.VerifySoftwareReconciliationEvidence(*record.task, *original.task, *result, original.authority, original.nonceHash, time.Now()) != nil || !bytes.Equal(result.Certificate, record.certificate.Raw) {
			return nil, ErrDenied
		}
		receipt, err := enrollment.SoftwareReconciliationReceipt(*result, time.Now())
		if err != nil {
			return nil, ErrDenied
		}
		encoded, err := json.Marshal(result)
		defer clear(encoded)
		if err != nil {
			return nil, ErrDenied
		}
		if len(record.resultWire) > 0 {
			if !bytes.Equal(record.resultWire, encoded) || record.resultHash != receipt.ResultHash {
				return nil, ErrDenied
			}
			reply.Receipt = receipt
			break
		}
		if record.status != "delivered" && record.status != "expired" {
			return nil, ErrDenied
		}
		var completed time.Time
		if err := tx.QueryRowContext(ctx, `UPDATE uem_agent_software_reconciliations SET status='reported',result=$2,result_hash=$3,outcome=$4,completed_at=clock_timestamp() WHERE id=$1 RETURNING completed_at`, result.Context.ID, encoded, receipt.ResultHash, result.Outcome.State).Scan(&completed); err != nil {
			return nil, err
		}
		if err := audit(ctx, tx, identity.Scope, "device:"+identity.ID, "software.reconciliation.reported", result.Context.ID); err != nil {
			return nil, err
		}
		if original.reconciliationID == "" && (original.status == "uncertain" || original.status == "restart_required") && result.Outcome.AllowsRelease(original.task.Context.Expectation) {
			if _, err := tx.ExecContext(ctx, `UPDATE uem_agent_software_tasks SET reconciliation_id=$2,reconciled_at=$3 WHERE id=$1 AND reconciliation_id IS NULL`, original.task.Context.TaskID, result.Context.ID, completed); err != nil {
				return nil, err
			}
			if err := audit(ctx, tx, identity.Scope, "device:"+identity.ID, "software.task.reconciled", original.task.Context.TaskID); err != nil {
				return nil, err
			}
			if err := cancelPendingSoftwareReconciliations(ctx, tx, identity.Scope, original.task.Context.TaskID); err != nil {
				return nil, err
			}
		}
		reply.Receipt = receipt
	default:
		return nil, ErrDenied
	}
	if err := softwareIdentityCurrent(ctx, tx, current); err != nil {
		return nil, err
	}
	if reply.Task != nil && !reply.Task.Context.Valid(time.Now()) {
		return nil, ErrDenied
	}
	if request.Submission != nil && enrollment.VerifySoftwareReconciliationSubmission(*request.Submission, *request.Result, current, certificate, time.Now()) != nil {
		return nil, ErrDenied
	}
	return reply, nil
}

func cancelPendingSoftwareReconciliations(ctx context.Context, tx *sql.Tx, scope Scope, originalID string) error {
	rows, err := tx.QueryContext(ctx, `UPDATE uem_agent_software_reconciliations SET status='cancelled',completed_at=clock_timestamp() WHERE original_task_id=$1 AND status='pending' RETURNING id`, originalID)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := audit(ctx, tx, scope, "system", "software.reconciliation.cancelled", id); err != nil {
			return err
		}
	}
	return nil
}
