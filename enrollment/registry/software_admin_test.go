package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
)

func (f *softwareFixture) adminTask(t *testing.T, scope Scope, id string, cancel bool) (*SoftwareTaskStatus, error) {
	t.Helper()
	tx, err := f.store.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var status *SoftwareTaskStatus
	if cancel {
		status, err = f.access.CancelSoftwareTaskInTransaction(t.Context(), tx, scope, id, "operator")
	} else {
		status, err = f.access.ReadSoftwareTaskInTransaction(t.Context(), tx, scope, id)
	}
	if err != nil {
		return nil, err
	}
	return status, tx.Commit()
}

func TestSoftwareAdministrativeHistoryIsScopedAndRedacted(t *testing.T) {
	for _, outcome := range []string{"observed", "uncertain", "restart_required"} {
		t.Run(outcome, func(t *testing.T) {
			f := newSoftwareFixture(t)
			task := f.queue(t)
			for _, scope := range []Scope{{TenantID: 1, SiteID: 3}, {TenantID: 2, SiteID: 1}, {TenantID: 1}} {
				if status, err := f.adminTask(t, scope, task.Context.TaskID, false); err == nil || status != nil {
					t.Fatal("foreign software history exposed")
				}
				if _, err := f.adminTask(t, scope, task.Context.TaskID, true); err == nil {
					t.Fatal("foreign task cancellation admitted")
				}
			}
			before, err := f.adminTask(t, f.identity.Scope, task.Context.TaskID, false)
			if err != nil || before.Status != "pending" || before.Outcome != nil || before.DeliveredAt != nil || before.CompletedAt != nil {
				t.Fatal("pending history invented execution", before, err)
			}
			if _, err = f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID}); err != nil {
				t.Fatal(err)
			}
			if _, err = f.submit(t, f.result(t, task, outcome)); err != nil {
				t.Fatal(err)
			}
			if err = f.store.RevokeIdentity(t.Context(), f.identity.Scope, f.identity.ID, "operator"); err != nil {
				t.Fatal(err)
			}
			status, err := f.adminTask(t, f.identity.Scope, task.Context.TaskID, false)
			if err != nil || status.Outcome == nil || status.Outcome.State != outcome || status.ID != task.Context.TaskID || status.AgentID != f.identity.ID || status.RevisionID != task.Context.RevisionID || status.PreparationID != task.Context.PreparationID || status.Operation != "install" || status.DeliveredAt == nil {
				t.Fatal("original historical evidence lost", status, err)
			}
			want := outcome
			if outcome == "observed" {
				want = "reported"
			}
			if status.Status != want {
				t.Fatal("receipt state confused with task state", status)
			}
			wire, err := json.Marshal(status)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"private-", "Nonce", "Envelope", "Certificate", "Recipient", "PlanHash", "TaskHash", "https://"} {
				if bytes.Contains(wire, []byte(secret)) {
					t.Fatal("private command material in administrative projection", secret)
				}
			}
			if _, err = f.adminTask(t, f.identity.Scope, task.Context.TaskID, true); err == nil {
				t.Fatal("reported or potentially executed task cancelled")
			}
		})
	}
}

func TestSoftwareAdministrativeCancellationIsAuditedAndNeverDelivered(t *testing.T) {
	f := newSoftwareFixture(t)
	task := f.queue(t)
	if _, err := f.store.db.Exec(`CREATE FUNCTION reject_software_cancel_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='software.task.cancelled' THEN RAISE EXCEPTION 'owned audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_software_cancel_audit BEFORE INSERT ON uem_agent_audit FOR EACH ROW EXECUTE FUNCTION reject_software_cancel_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.adminTask(t, f.identity.Scope, task.Context.TaskID, true); err == nil {
		t.Fatal("cancellation survived failed audit")
	}
	status, err := f.adminTask(t, f.identity.Scope, task.Context.TaskID, false)
	if err != nil || status.Status != "pending" {
		t.Fatal("failed cancellation lost pending task", status, err)
	}
	if _, err = f.store.db.Exec(`DROP TRIGGER reject_software_cancel_audit ON uem_agent_audit`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		status, err = f.adminTask(t, f.identity.Scope, task.Context.TaskID, true)
		if err != nil || status.Status != "cancelled" || status.CompletedAt == nil || status.DeliveredAt != nil || status.Outcome != nil {
			t.Fatal("cancellation changed intent or invented execution", status, err)
		}
	}
	var count int
	if err = f.store.db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE resource_id=$1 AND action='software.task.cancelled'`, task.Context.TaskID).Scan(&count); err != nil || count != 1 {
		t.Fatal("cancel retry duplicated audit", count, err)
	}
	reply, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID})
	if err != nil || reply.Task != nil {
		t.Fatal("cancelled installer delivered", err)
	}
	_ = f.queue(t)
}

func TestSoftwareAdministrativeCancellationSerializesWithDelivery(t *testing.T) {
	f := newSoftwareFixture(t)
	task := f.queue(t)
	tx, err := f.store.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = f.access.CancelSoftwareTaskInTransaction(t.Context(), tx, f.identity.Scope, task.Context.TaskID, "operator"); err != nil {
		t.Fatal(err)
	}
	type received struct {
		reply *enrollment.SoftwareReply
		err   error
	}
	done := make(chan received, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	go func() {
		reply, err := f.call(ctx, enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID})
		done <- received{reply, err}
	}()
	select {
	case <-done:
		t.Fatal("delivery escaped an uncommitted cancellation")
	case <-time.After(50 * time.Millisecond):
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	value := <-done
	if value.err != nil || value.reply.Task != nil {
		t.Fatal("cancellation winner did not exclude delivery", value.err)
	}
	next := f.queue(t)
	if _, err = f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.adminTask(t, f.identity.Scope, next.Context.TaskID, true); err == nil {
		t.Fatal("delivery winner was cancelled")
	}
	status, err := f.adminTask(t, f.identity.Scope, next.Context.TaskID, false)
	if err != nil || status.Status != "delivered" || status.Outcome != nil {
		t.Fatal("delivery winner evidence changed", status, err)
	}
}
