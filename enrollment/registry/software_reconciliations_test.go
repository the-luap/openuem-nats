package registry

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

func (f *softwareFixture) reconciliationCall(ctx context.Context, request enrollment.SoftwareReconciliationRequest) (*enrollment.SoftwareReconciliationReply, error) {
	request.Version, request.Protocol = enrollment.SoftwareReconciliationVersion, enrollment.SoftwareReconciliationProtocol
	if request.AgentID == "" {
		request.AgentID = f.identity.ID
	}
	tx, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	reply, err := f.access.HandleSoftwareReconciliationInTransaction(ctx, tx, *f.identity, request)
	if err != nil {
		return nil, err
	}
	return reply, tx.Commit()
}

func (f *softwareFixture) queueReconciliation(ctx context.Context, originalID, id string, expires time.Time) (*enrollment.SoftwareReconciliationTask, error) {
	tx, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	task, err := f.store.QueueSoftwareReconciliationInTransaction(ctx, tx, f.identity.Scope, f.identity.ID, originalID, id, expires, "operator")
	if err != nil {
		return nil, err
	}
	return task, tx.Commit()
}

func (f *softwareFixture) tryQueueSoftware(ctx context.Context) (*enrollment.SoftwareTask, error) {
	tx, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	task, err := f.store.QueueSoftwareTaskInTransaction(ctx, tx, f.identity.Scope, f.identity.ID, uuid.NewString(), uuid.NewString(), uuid.NewString(), softwarePlan(), time.Now().Add(5*time.Minute), "operator")
	if err != nil {
		return nil, err
	}
	return task, tx.Commit()
}

func prepareSoftwareReconciliation(t *testing.T, outcome string) (*softwareFixture, *enrollment.SoftwareTask, *enrollment.SoftwareReconciliationTask) {
	t.Helper()
	f := newSoftwareFixture(t)
	original := f.queue(t)
	if _, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID}); err != nil {
		t.Fatal(err)
	}
	if outcome == "missing_receipt" {
		// Model retained delivery uncertainty before the endpoint's first receipt.
		if _, err := f.store.db.Exec(`UPDATE uem_agent_software_tasks SET status='uncertain' WHERE id=$1`, original.Context.TaskID); err != nil {
			t.Fatal(err)
		}
	} else if _, err := f.submit(t, f.result(t, original, outcome)); err != nil {
		t.Fatal(err)
	}
	task, err := f.queueReconciliation(t.Context(), original.Context.TaskID, uuid.NewString(), time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal("reconciliation queue failed", err)
	}
	return f, original, task
}

func (f *softwareFixture) reconciliationResult(t *testing.T, original *enrollment.SoftwareTask, task *enrollment.SoftwareReconciliationTask, state string) *enrollment.SoftwareReconciliationResult {
	t.Helper()
	secret, err := f.key.Open(*original, f.authority, original.Context.Identity, original.Context.RecipientID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	outcome := enrollment.SoftwareReconciliationOutcome{State: state, Admission: enrollment.SoftwareBootSession{Sequence: 19, SystemProcessCreated: 133000000000000000}, Current: enrollment.SoftwareBootSession{Sequence: 20, SystemProcessCreated: 133000100000000000}, Observation: enrollment.SoftwareObservation{State: "present", Version: "1.2.3"}}
	nonce := secret.Nonce()
	defer clear(nonce)
	switch state {
	case "drifted":
		outcome.Observation.Version = "9.0.0"
	case "unknown":
		outcome.Observation = enrollment.SoftwareObservation{State: "unknown"}
	case "waiting_for_boot":
		outcome.Current = outcome.Admission
		outcome.Observation = enrollment.SoftwareObservation{State: "unknown"}
	case "unavailable":
		outcome.Admission, outcome.Current = enrollment.SoftwareBootSession{}, enrollment.SoftwareBootSession{}
		outcome.Observation = enrollment.SoftwareObservation{State: "unknown"}
		nonce = nil
	}
	hash, err := task.Digest()
	if err != nil {
		t.Fatal(err)
	}
	result, err := enrollment.SignSoftwareReconciliationResult(task.Context, hash, nonce, outcome, f.cert, f.signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func (f *softwareFixture) submitReconciliation(ctx context.Context, result *enrollment.SoftwareReconciliationResult) (*enrollment.SoftwareReconciliationReply, error) {
	identity := enrollment.SoftwareIdentity{AgentID: f.identity.ID, TenantID: f.identity.TenantID, SiteID: f.identity.SiteID, CertificateHash: digest(f.cert.Raw)}
	proof, err := enrollment.SignSoftwareReconciliationSubmission(*result, identity, f.cert, f.signer, time.Now())
	if err != nil {
		return nil, err
	}
	return f.reconciliationCall(ctx, enrollment.SoftwareReconciliationRequest{Action: "result", Result: result, Submission: proof})
}

func (f *softwareFixture) readReconciliation(t *testing.T, scope Scope, id string, cancel bool) (*SoftwareReconciliationStatus, error) {
	t.Helper()
	tx, err := f.store.db.BeginTx(t.Context(), nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var status *SoftwareReconciliationStatus
	if cancel {
		status, err = f.access.CancelSoftwareReconciliationInTransaction(t.Context(), tx, scope, id, "operator")
	} else {
		status, err = f.access.ReadSoftwareReconciliationInTransaction(t.Context(), tx, scope, id)
	}
	if err != nil {
		return nil, err
	}
	return status, tx.Commit()
}

func TestSoftwareReconciliationRegistryPreservesExecutionAndReleasesOnlyDefiniteLaterBoot(t *testing.T) {
	for _, originalState := range []string{"uncertain", "restart_required", "missing_receipt"} {
		for _, state := range []string{"observed", "drifted", "unknown", "waiting_for_boot", "unavailable"} {
			t.Run(originalState+"/"+state, func(t *testing.T) {
				f, original, task := prepareSoftwareReconciliation(t, originalState)
				retained := func() string {
					t.Helper()
					var value string
					if err := f.store.db.QueryRow(`SELECT (to_jsonb(t)-'reconciliation_id'-'reconciled_at')::text FROM uem_agent_software_tasks t WHERE id=$1`, original.Context.TaskID).Scan(&value); err != nil {
						t.Fatal(err)
					}
					return value
				}
				before := retained()
				if _, err := f.tryQueueSoftware(t.Context()); err == nil {
					t.Fatal("review alone released the original reservation")
				}
				result := f.reconciliationResult(t, original, task, state)
				if _, err := f.submitReconciliation(t.Context(), result); err == nil {
					t.Fatal("result accepted before delivery")
				}
				for range 2 {
					reply, err := f.reconciliationCall(t.Context(), enrollment.SoftwareReconciliationRequest{Action: "poll"})
					if err != nil || reply.Task == nil || !reply.Task.Context.Equal(task.Context) {
						t.Fatal("exact read-only delivery failed", err)
					}
				}
				var receipt *enrollment.SoftwareReceipt
				for range 2 {
					reply, err := f.submitReconciliation(t.Context(), result)
					if err != nil || reply.Receipt == nil {
						t.Fatal("result/retry failed", err)
					}
					if receipt != nil && *receipt != *reply.Receipt {
						t.Fatal("retry changed receipt")
					}
					receipt = reply.Receipt
				}
				if retained() != before {
					t.Fatal("reconciliation changed the original execution evidence")
				}
				status, err := f.readReconciliation(t, f.identity.Scope, task.Context.ID, false)
				released := state == "observed" || state == "drifted"
				if err != nil || status.Status != "reported" || status.Outcome == nil || status.Outcome.State != state || status.ReleasesReservation != released {
					t.Fatal("safe reconciliation projection disagrees", err)
				}
				old, err := f.adminTask(t, f.identity.Scope, original.Context.TaskID, false)
				if err != nil || (old.ReconciliationID != "") != released || (old.ReconciledAt != nil) != released {
					t.Fatal("original release linkage disagrees", err)
				}
				wire, _ := json.Marshal(status)
				for _, secret := range []string{"private-", "Nonce", "Envelope", "Certificate", "https://", "TaskHash"} {
					if bytes.Contains(wire, []byte(secret)) {
						t.Fatal("administrative projection leaked protected material")
					}
				}
				var audits int
				if err := f.store.db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE resource_id=$1 AND action='software.reconciliation.reported'`, task.Context.ID).Scan(&audits); err != nil || audits != 1 {
					t.Fatal("receipt retries duplicated audit", audits, err)
				}
				if _, err := f.tryQueueSoftware(t.Context()); (err == nil) != released {
					t.Fatal("reservation state disagrees with authenticated outcome", err)
				}
				if _, err := f.readReconciliation(t, f.identity.Scope, task.Context.ID, true); err == nil {
					t.Fatal("accepted evidence cancelled")
				}
				if !released {
					if _, err := f.store.db.Exec(`UPDATE uem_agent_software_tasks SET reconciliation_id=$2,reconciled_at=(SELECT completed_at FROM uem_agent_software_reconciliations WHERE id=$2) WHERE id=$1`, original.Context.TaskID, task.Context.ID); err == nil {
						t.Fatal("database released an indefinite observation")
					}
					if _, err := f.queueReconciliation(t.Context(), original.Context.TaskID, uuid.NewString(), time.Now().Add(5*time.Minute)); err != nil {
						t.Fatal("explicit subsequent observation blocked", err)
					}
				}
			})
		}
	}
}

func TestSoftwareReconciliationAuditFailuresRollbackDeliveryEvidenceAndRelease(t *testing.T) {
	for _, action := range []string{"software.reconciliation.delivered", "software.reconciliation.reported", "software.task.reconciled"} {
		t.Run(action, func(t *testing.T) {
			f, original, task := prepareSoftwareReconciliation(t, "restart_required")
			result := f.reconciliationResult(t, original, task, "observed")
			if action != "software.reconciliation.delivered" {
				if _, err := f.reconciliationCall(t.Context(), enrollment.SoftwareReconciliationRequest{Action: "poll"}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.store.db.Exec(fmt.Sprintf(`CREATE FUNCTION reject_reconciliation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='%s' THEN RAISE EXCEPTION 'owned audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_reconciliation_audit BEFORE INSERT ON uem_agent_audit FOR EACH ROW EXECUTE FUNCTION reject_reconciliation_audit()`, action)); err != nil {
				t.Fatal(err)
			}
			var err error
			if action == "software.reconciliation.delivered" {
				_, err = f.reconciliationCall(t.Context(), enrollment.SoftwareReconciliationRequest{Action: "poll"})
			} else {
				_, err = f.submitReconciliation(t.Context(), result)
			}
			if err == nil {
				t.Fatal("audit failure acknowledged")
			}
			status, err := f.readReconciliation(t, f.identity.Scope, task.Context.ID, false)
			if err != nil || status.Outcome != nil || status.ReleasesReservation || action == "software.reconciliation.delivered" && status.DeliveredAt != nil {
				t.Fatal("failed audit retained a partial transition", err)
			}
			if _, err := f.tryQueueSoftware(t.Context()); err == nil {
				t.Fatal("failed commit released reservation")
			}
			if _, err := f.store.db.Exec(`DROP TRIGGER reject_reconciliation_audit ON uem_agent_audit`); err != nil {
				t.Fatal(err)
			}
			if action == "software.reconciliation.delivered" {
				if _, err := f.reconciliationCall(t.Context(), enrollment.SoftwareReconciliationRequest{Action: "poll"}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.submitReconciliation(t.Context(), result); err != nil {
				t.Fatal("retained exact retry failed", err)
			}
		})
	}
}

func TestSoftwareReconciliationConcurrentQueueAndReceiptAreIdempotent(t *testing.T) {
	f, original, task := prepareSoftwareReconciliation(t, "uncertain")
	expires := time.Unix(task.Context.ExpiresAt, 0)
	var group sync.WaitGroup
	for range 6 {
		group.Go(func() {
			repeated, err := f.queueReconciliation(t.Context(), original.Context.TaskID, task.Context.ID, expires)
			if err != nil || repeated == nil || !repeated.Context.Equal(task.Context) {
				t.Error("exact review retry failed", err)
			}
		})
	}
	group.Wait()
	if _, err := f.queueReconciliation(t.Context(), original.Context.TaskID, uuid.NewString(), expires); err == nil {
		t.Fatal("competing active observation admitted")
	}
	if _, err := f.reconciliationCall(t.Context(), enrollment.SoftwareReconciliationRequest{Action: "poll"}); err != nil {
		t.Fatal(err)
	}
	result := f.reconciliationResult(t, original, task, "observed")
	for range 6 {
		group.Go(func() {
			if _, err := f.submitReconciliation(t.Context(), result); err != nil {
				t.Error("concurrent exact receipt failed", err)
			}
		})
	}
	group.Wait()
	var count int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE resource_id=$1 AND action='software.task.reconciled'`, original.Context.TaskID).Scan(&count); err != nil || count != 1 {
		t.Fatal("concurrent release duplicated audit", count, err)
	}
}

func TestSoftwareReconciliationRejectsForeignScopeWrongNonceAndRetainsCancellation(t *testing.T) {
	f, original, task := prepareSoftwareReconciliation(t, "uncertain")
	for _, scope := range []Scope{{TenantID: 2, SiteID: 1}, {TenantID: 1, SiteID: 3}, {TenantID: 1}} {
		if _, err := f.readReconciliation(t, scope, task.Context.ID, false); err == nil {
			t.Fatal("foreign observation history read")
		}
		if _, err := f.readReconciliation(t, scope, task.Context.ID, true); err == nil {
			t.Fatal("foreign observation cancelled")
		}
	}
	status, err := f.readReconciliation(t, f.identity.Scope, task.Context.ID, true)
	if err != nil || status.Status != "cancelled" || status.ReleasesReservation {
		t.Fatal("pending cancellation failed", err)
	}
	if _, err := f.tryQueueSoftware(t.Context()); err == nil {
		t.Fatal("observation cancellation released executable reservation")
	}
	if reply, err := f.reconciliationCall(t.Context(), enrollment.SoftwareReconciliationRequest{Action: "poll"}); err != nil || reply.Task != nil {
		t.Fatal("cancelled read-only task delivered", err)
	}
	task, err = f.queueReconciliation(t.Context(), original.Context.TaskID, uuid.NewString(), time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.reconciliationCall(t.Context(), enrollment.SoftwareReconciliationRequest{Action: "poll"}); err != nil {
		t.Fatal(err)
	}
	result := f.reconciliationResult(t, original, task, "observed")
	wrong, err := enrollment.SignSoftwareReconciliationResult(task.Context, result.TaskHash, bytes.Repeat([]byte{1}, 32), result.Outcome, f.cert, f.signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.submitReconciliation(t.Context(), wrong); err == nil {
		t.Fatal("signed result with wrong original nonce accepted")
	}
	if _, err := f.submitReconciliation(t.Context(), result); err != nil {
		t.Fatal(err)
	}
	changed := *result
	changed.Outcome.State, changed.Outcome.Observation.Version = "drifted", "9.0.0"
	if _, err := f.submitReconciliation(t.Context(), &changed); err == nil {
		t.Fatal("changed receipt accepted")
	}
	for _, statement := range []string{
		`DELETE FROM uem_agent_software_reconciliations WHERE id=$1`,
		`UPDATE uem_agent_software_reconciliations SET envelope='{}' WHERE id=$1`,
		`UPDATE uem_agent_software_reconciliations SET result='{}' WHERE id=$1`,
		`UPDATE uem_agent_software_reconciliations SET outcome='unknown' WHERE id=$1`,
	} {
		if _, err := f.store.db.Exec(statement, task.Context.ID); err == nil {
			t.Fatal("immutable reconciliation was altered")
		}
	}
	if _, err := f.store.db.Exec(`TRUNCATE uem_agent_software_reconciliations CASCADE`); err == nil {
		t.Fatal("reconciliation history truncated")
	}
	if _, err := f.store.db.Exec(`UPDATE uem_agent_software_tasks SET reconciliation_id=NULL,reconciled_at=NULL WHERE id=$1`, original.Context.TaskID); err == nil {
		t.Fatal("release erased")
	}
	if err := f.store.RevokeIdentity(t.Context(), f.identity.Scope, f.identity.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	status, err = f.readReconciliation(t, f.identity.Scope, task.Context.ID, false)
	if err != nil || !status.ReleasesReservation || status.Outcome == nil || status.Outcome.State != "observed" {
		t.Fatal("revocation erased historical proof", err)
	}
	if _, err := f.submitReconciliation(t.Context(), result); err == nil {
		t.Fatal("revoked identity submitted a receipt")
	}
}

func TestSoftwareReconciliationLateOriginalReceiptPreservesReleaseAndNewReservation(t *testing.T) {
	f, original, task := prepareSoftwareReconciliation(t, "missing_receipt")
	if _, err := f.reconciliationCall(t.Context(), enrollment.SoftwareReconciliationRequest{Action: "poll"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.submitReconciliation(t.Context(), f.reconciliationResult(t, original, task, "observed")); err != nil {
		t.Fatal(err)
	}
	if reply, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID}); err != nil || reply.Task != nil {
		t.Fatal("reconciled original without receipt redelivered", err)
	}
	newTask, err := f.tryQueueSoftware(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.submit(t, f.result(t, original, "restart_required")); err != nil {
		t.Fatal("late immutable original receipt rejected", err)
	}
	status, err := f.adminTask(t, f.identity.Scope, original.Context.TaskID, false)
	if err != nil || status.Status != "restart_required" || status.ReconciliationID != task.Context.ID || status.Outcome == nil {
		t.Fatal("late receipt changed release evidence", err)
	}
	if _, err := f.tryQueueSoftware(t.Context()); err == nil {
		t.Fatal("late original receipt released a different active task")
	}
	reply, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID})
	if err != nil || reply.Task == nil || reply.Task.Context.TaskID != newTask.Context.TaskID {
		t.Fatal("new reservation confused with reconciled task", err)
	}
	if strings.Contains(fmt.Sprint(status), "private-license") {
		t.Fatal("private plan leaked through status")
	}
}

func (f *softwareFixture) renewReconciliationIdentity(t *testing.T) {
	t.Helper()
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Broker.Wipe)
	var root, sealed []byte
	if err := f.store.db.QueryRow(`SELECT certificate,encrypted_key FROM uem_agent_authorities WHERE tenant_id=$1`, f.identity.TenantID).Scan(&root, &sealed); err != nil {
		t.Fatal(err)
	}
	raw, err := f.store.open(sealed, fmt.Sprintf("%d/authority/key", f.identity.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	ca, issuer, err := parseAuthority(root, raw)
	if err != nil {
		t.Fatal(err)
	}
	issued, expires, err := issueCertificate(ca, issuer, f.identity.ID, &keys.Certificate.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := softwareCertificate(issued)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE uem_agent_identities SET certificate=$2,certificate_hash=$3,certificate_key_hash=$4,certificate_expires_at=$5 WHERE id=$1`, f.identity.ID, issued, digest(cert.Raw), digest(public), expires); err != nil {
		t.Fatal(err)
	}
	f.cert, f.signer = cert, keys.Certificate
}

func TestSoftwareReconciliationRequiresCurrentSubmissionAndCancelsUndeliveredGenerations(t *testing.T) {
	f, original, task := prepareSoftwareReconciliation(t, "uncertain")
	if _, err := f.reconciliationCall(t.Context(), enrollment.SoftwareReconciliationRequest{Action: "poll"}); err != nil {
		t.Fatal(err)
	}
	result := f.reconciliationResult(t, original, task, "observed")
	oldProof, err := enrollment.SignSoftwareReconciliationSubmission(*result, task.Context.Identity, f.cert, f.signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		f.renewReconciliationIdentity(t)
	}
	if _, err := f.reconciliationCall(t.Context(), enrollment.SoftwareReconciliationRequest{Action: "result", Result: result, Submission: oldProof}); err == nil {
		t.Fatal("retired generation submitted through a stale broker session")
	}
	if _, err := f.submitReconciliation(t.Context(), result); err != nil {
		t.Fatal("current proof could not recover historical observation", err)
	}
	wire, _ := json.Marshal(result)
	var stored []byte
	if err := f.store.db.QueryRow(`SELECT result FROM uem_agent_software_reconciliations WHERE id=$1`, task.Context.ID).Scan(&stored); err != nil || !bytes.Equal(wire, stored) {
		t.Fatal("renewal changed immutable signed observation", err)
	}
	f, original, task = prepareSoftwareReconciliation(t, "restart_required")
	f.renewReconciliationIdentity(t)
	status, err := f.readReconciliation(t, f.identity.Scope, task.Context.ID, false)
	if err != nil || status.Status != "cancelled" || status.ReleasesReservation {
		t.Fatal("old undelivered generation survived renewal", err)
	}
	if reply, err := f.reconciliationCall(t.Context(), enrollment.SoftwareReconciliationRequest{Action: "poll"}); err != nil || reply.Task != nil {
		t.Fatal("old generation delivered after renewal", err)
	}
	if _, err := f.queueReconciliation(t.Context(), original.Context.TaskID, uuid.NewString(), time.Now().Add(5*time.Minute)); err != nil {
		t.Fatal("new explicit current-generation reconciliation rejected", err)
	}
}

func TestSoftwareReconciliationQueueAuditAndEvidenceTamperingFailClosed(t *testing.T) {
	f, original, task := prepareSoftwareReconciliation(t, "uncertain")
	if _, err := f.readReconciliation(t, f.identity.Scope, task.Context.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`CREATE FUNCTION reject_reconciliation_queue() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='software.reconciliation.queued' THEN RAISE EXCEPTION 'owned audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_reconciliation_queue BEFORE INSERT ON uem_agent_audit FOR EACH ROW EXECUTE FUNCTION reject_reconciliation_queue()`); err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	if _, err := f.queueReconciliation(t.Context(), original.Context.TaskID, id, time.Now().Add(5*time.Minute)); err == nil {
		t.Fatal("queue audit failure accepted")
	}
	var exists bool
	if err := f.store.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM uem_agent_software_reconciliations WHERE id=$1)`, id).Scan(&exists); err != nil || exists {
		t.Fatal("failed queue retained partial intent", err)
	}
	if _, err := f.store.db.Exec(`DROP TRIGGER reject_reconciliation_queue ON uem_agent_audit`); err != nil {
		t.Fatal(err)
	}
	task, err := f.queueReconciliation(t.Context(), original.Context.TaskID, id, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.reconciliationCall(t.Context(), enrollment.SoftwareReconciliationRequest{Action: "poll"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.submitReconciliation(t.Context(), f.reconciliationResult(t, original, task, "observed")); err != nil {
		t.Fatal(err)
	}
	// Model damaged restored state by deliberately bypassing the isolated test
	// table's guard; normal SQL above cannot change these retained bytes.
	if _, err := f.store.db.Exec(`ALTER TABLE uem_agent_software_reconciliations DISABLE TRIGGER uem_agent_software_reconciliation_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE uem_agent_software_reconciliations SET result='{}' WHERE id=$1`, task.Context.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.adminTask(t, f.identity.Scope, original.Context.TaskID, false); err == nil {
		t.Fatal("original history accepted damaged release proof")
	}
	if _, err := f.readReconciliation(t, f.identity.Scope, task.Context.ID, false); err == nil {
		t.Fatal("damaged observation evidence accepted")
	}
}

func TestSoftwareReconciliationMigrationRetainsExistingUncertainty(t *testing.T) {
	f := newSoftwareFixture(t)
	original := f.queue(t)
	if _, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.submit(t, f.result(t, original, "restart_required")); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := f.store.db.QueryRow(`SELECT (to_jsonb(t)-'reconciliation_id'-'reconciled_at')::text FROM uem_agent_software_tasks t WHERE id=$1`, original.Context.TaskID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`DROP TRIGGER uem_agent_software_reconciliation_identity_change ON uem_agent_identities; DROP FUNCTION uem_agent_software_reconciliation_identity_change(); ALTER TABLE uem_agent_software_tasks DROP COLUMN reconciliation_id CASCADE; ALTER TABLE uem_agent_software_tasks DROP COLUMN reconciled_at; DROP TABLE uem_agent_software_reconciliations; DROP FUNCTION uem_agent_software_reconciliation_guard(); DELETE FROM uem_agent_migrations WHERE name='migrations/013_software_reconciliations.sql'`); err != nil {
		t.Fatal(err)
	}
	legacy, err := migrations.ReadFile("migrations/012_windows_software_tasks.sql")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(legacy), "CREATE FUNCTION uem_agent_software_task_guard()")
	end := strings.Index(string(legacy)[start:], "CREATE TRIGGER uem_agent_software_task_guard") + start
	guard := strings.Replace(string(legacy)[start:end], "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
	if _, err := f.store.db.Exec(guard + `CREATE UNIQUE INDEX uem_agent_software_active ON uem_agent_software_tasks(device_id) WHERE status IN ('pending','delivered','uncertain','restart_required');`); err != nil {
		t.Fatal(err)
	}
	if f.access.SoftwareReady(t.Context()) {
		t.Fatal("old schema advertised reconciliation readiness")
	}
	if err := f.store.Migrate(t.Context()); err != nil {
		t.Fatal("existing-data migration failed", err)
	}
	var after string
	if err := f.store.db.QueryRow(`SELECT (to_jsonb(t)-'reconciliation_id'-'reconciled_at')::text FROM uem_agent_software_tasks t WHERE id=$1`, original.Context.TaskID).Scan(&after); err != nil || after != before {
		t.Fatal("migration changed retained execution evidence", err)
	}
	if !f.access.SoftwareReady(t.Context()) {
		t.Fatal("migrated schema unavailable")
	}
	if _, err := f.tryQueueSoftware(t.Context()); err == nil {
		t.Fatal("migration silently released retained restart uncertainty")
	}
	if _, err := f.queueReconciliation(t.Context(), original.Context.TaskID, uuid.NewString(), time.Now().Add(5*time.Minute)); err != nil {
		t.Fatal("migrated task cannot be explicitly reconciled", err)
	}
}

func TestSoftwareReconciliationOfflineReceiptCancelsSupersededPendingObservation(t *testing.T) {
	f, original, preceding := prepareSoftwareReconciliation(t, "uncertain")
	if _, err := f.readReconciliation(t, f.identity.Scope, preceding.Context.ID, true); err != nil {
		t.Fatal(err)
	}
	// Use a directly signed short-lived fixture to exercise real expiration
	// without waiting for the production queue's minimum one-minute deadline.
	var root, sealed []byte
	if err := f.store.db.QueryRow(`SELECT certificate,encrypted_key FROM uem_agent_authorities WHERE tenant_id=1`).Scan(&root, &sealed); err != nil {
		t.Fatal(err)
	}
	raw, err := f.store.open(sealed, "1/authority/key")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	ca, issuer, err := parseAuthority(root, raw)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c := preceding.Context
	c.ID = uuid.NewString()
	c.CreatedAt, c.ExpiresAt = now.Unix(), now.Add(8*time.Second).Unix()
	task, err := enrollment.SignSoftwareReconciliationTask(c, ca, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := json.Marshal(task)
	contextWire, _ := json.Marshal(c)
	hash, _ := task.Digest()
	if _, err := f.store.db.Exec(`INSERT INTO uem_agent_software_reconciliations(id,tenant_id,site_id,device_id,original_task_id,certificate_hash,certificate,task_hash,task_context,envelope,actor,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'operator',$11,$12)`, c.ID, c.Identity.TenantID, c.Identity.SiteID, c.Identity.AgentID, c.Original.TaskID, c.Identity.CertificateHash, f.cert.Raw, hash, contextWire, envelope, time.Unix(c.CreatedAt, 0), time.Unix(c.ExpiresAt, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.reconciliationCall(t.Context(), enrollment.SoftwareReconciliationRequest{Action: "poll"}); err != nil {
		t.Fatal(err)
	}
	result := f.reconciliationResult(t, original, task, "observed")
	wait := time.NewTimer(time.Until(time.Unix(c.ExpiresAt+1, 0)))
	defer wait.Stop()
	select {
	case <-wait.C:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	next, err := f.queueReconciliation(t.Context(), original.Context.TaskID, uuid.NewString(), time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal("expired observation blocked new explicit review", err)
	}
	if _, err := f.tryQueueSoftware(t.Context()); err == nil {
		t.Fatal("observation expiry released original execution")
	}
	if _, err := f.submitReconciliation(t.Context(), result); err != nil {
		t.Fatal("offline receipt signed before expiry was lost", err)
	}
	status, err := f.readReconciliation(t, f.identity.Scope, task.Context.ID, false)
	if err != nil || status.Status != "reported" || !status.ReleasesReservation {
		t.Fatal("late receipt did not retain its release", err)
	}
	status, err = f.readReconciliation(t, f.identity.Scope, next.Context.ID, false)
	if err != nil || status.Status != "cancelled" || status.ReleasesReservation {
		t.Fatal("superseded pending observation remained active", err)
	}
	if _, err := f.tryQueueSoftware(t.Context()); err != nil {
		t.Fatal("authenticated late receipt did not release reservation", err)
	}
}
