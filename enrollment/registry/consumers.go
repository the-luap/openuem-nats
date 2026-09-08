package registry

import (
	"context"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

// PendingCommandConsumers leases bounded work to trusted provisioning replicas.
// Completed entries are periodically checked again to recover from broker data
// loss or a process crash between a broker mutation and database acknowledgment.
func (s *AccessStore) PendingCommandConsumers(ctx context.Context, limit int) ([]enrollment.CommandConsumerWork, error) {
	if limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Time passing cannot fire a trigger. Expiry work is bounded separately so
	// a large cohort expiring together cannot monopolize a poll transaction.
	_, err = tx.ExecContext(ctx, `WITH expired AS (
        SELECT q.device_id FROM uem_agent_command_consumers q
        JOIN uem_agent_identities i ON i.id=q.device_id
        WHERE q.desired_active AND i.certificate_expires_at<=clock_timestamp()
        ORDER BY i.certificate_expires_at LIMIT 256 FOR UPDATE OF q SKIP LOCKED
    ) UPDATE uem_agent_command_consumers q SET desired_active=false,revision=q.revision+1,
        attempted_at=NULL,lease_token=NULL,reconcile_at=clock_timestamp()
      FROM expired WHERE q.device_id=expired.device_id`)
	if err != nil {
		return nil, err
	}
	lease := uuid.NewString()
	rows, err := tx.QueryContext(ctx, `WITH pending AS (
        SELECT device_id FROM uem_agent_command_consumers
        WHERE (completed_revision<>revision OR reconcile_at<=clock_timestamp())
          AND (attempted_at IS NULL OR attempted_at<clock_timestamp()-INTERVAL '30 seconds')
        ORDER BY attempted_at NULLS FIRST,reconcile_at,device_id
        LIMIT $1 FOR UPDATE SKIP LOCKED
    ) UPDATE uem_agent_command_consumers q SET attempted_at=clock_timestamp(),lease_token=$2
      FROM pending WHERE q.device_id=pending.device_id
      RETURNING q.device_id,q.desired_active,q.revision,q.lease_token`, limit, lease)
	if err != nil {
		return nil, err
	}
	work := []enrollment.CommandConsumerWork{}
	for rows.Next() {
		var item enrollment.CommandConsumerWork
		if err = rows.Scan(&item.DeviceID, &item.Active, &item.Revision, &item.LeaseID); err != nil {
			rows.Close()
			return nil, err
		}
		work = append(work, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return work, nil
}

// CompleteCommandConsumer acknowledges only the leased version. A stale broker
// operation can finish after a newer deletion/creation; request another check of
// the current desired state instead of incorrectly marking the stale state done.
func (s *AccessStore) CompleteCommandConsumer(ctx context.Context, item enrollment.CommandConsumerWork) error {
	if !enrollment.ValidDeviceID(item.DeviceID) || item.Revision < 1 || !enrollment.ValidDeviceID(item.LeaseID) {
		return ErrInvalid
	}
	_, err := s.db.ExecContext(ctx, `UPDATE uem_agent_command_consumers SET
        completed_revision=CASE WHEN revision=$2 AND lease_token=$3 AND desired_active=$4 THEN revision ELSE 0 END,
        reconcile_at=CASE WHEN revision=$2 AND lease_token=$3 AND desired_active=$4 THEN clock_timestamp()+INTERVAL '1 hour' ELSE clock_timestamp() END
      WHERE device_id=$1`, item.DeviceID, item.Revision, item.LeaseID, item.Active)
	return err
}
