package registry

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

func completedHistoricalRotation(t *testing.T, f *rotationFixture, outcome string) (*enrollment.RotationTask, []byte) {
	t.Helper()
	task := f.queue(t)
	if _, err := f.access.HandleRotation(t.Context(), *f.identity, f.pollRequest()); err != nil {
		t.Fatal(err)
	}
	request := f.result(t, task.Context, outcome)
	if _, err := f.access.HandleRotation(t.Context(), *f.identity, request); err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(request.Result)
	return task, wire
}

func TestHistoricalRotationUsesAuthenticatedRetiredSourceCertificate(t *testing.T) {
	f := newIdentityRenewalFixture(t)
	f.s.renewalClock = nil
	if _, err := f.s.db.Exec(`UPDATE uem_agent_identities SET platform='macos' WHERE id=$1`, f.source.DeviceID); err != nil {
		t.Fatal(err)
	}
	f.source.Platform = "macos"
	var err error
	f.request, err = enrollment.NewRenewalRequest(f.source, f.current, f.candidate, f.request.RequestID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	prepared, _, confirm := f.prepareConfirmation(t)
	access, _ := NewAccessStore(f.s.db)
	identity, err := access.ActiveIdentity(t.Context(), f.source.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(f.source.Certificate)
	agent, err := enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(agent.Close)
	console, err := enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(console.Close)
	recipient, _, _ := testRegisterRecovery(t, access, identity, cert, f.current.Certificate, agent)
	rf := &rotationFixture{s: f.s, access: access, identity: identity, cert: cert, signer: f.current.Certificate, agent: agent, console: console, recipient: recipient, nonce: bytes.Repeat([]byte{8}, 32)}
	rotation, wire := completedHistoricalRotation(t, rf, "rotated")
	if err = historyTx(t, rf, func(tx *sql.Tx) error {
		return f.s.AcknowledgeRotationReconciliationInTransaction(t.Context(), tx, identity.Scope, identity.ID, rotation.Context.Binding.TaskID, digest(wire), "console")
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.ConfirmIdentityRenewal(t.Context(), *confirm); err != nil {
		t.Fatal(err)
	}
	// This isolated fixture recreates older console history after an already
	// completed handoff. The new registry must use the authenticated SOURCE,
	// never treat a merely issued candidate as authority for the old receipt.
	if _, err = f.s.db.Exec(`ALTER TABLE uem_agent_rotation_reconciliations DISABLE TRIGGER uem_agent_rotation_reconciliation_immutable; DELETE FROM uem_agent_rotation_reconciliations; ALTER TABLE uem_agent_rotation_reconciliations ENABLE TRIGGER uem_agent_rotation_reconciliation_immutable`); err != nil {
		t.Fatal(err)
	}
	rf.identity, err = access.ActiveIdentity(t.Context(), identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	rf.cert, err = enrollment.ValidateResponse(prepared.Response, f.source.Origin, &f.candidate.Certificate.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rf.signer = f.candidate.Certificate
	rf.recipient, _, _ = testRegisterRecovery(t, access, rf.identity, rf.cert, rf.signer, agent)
	check, nonce := historicalCheck(t, rf, rotation, wire)
	if err = historyTx(t, rf, func(tx *sql.Tx) error {
		return f.s.QueueHistoricalRotationCheckInTransaction(t.Context(), tx, rf.identity.Scope, rf.identity.ID, check, "console")
	}); err != nil {
		t.Fatal("retired source evidence not recovered", err)
	}
	reportHistoricalCheck(t, rf, check, nonce, "valid")
	if err = historyTx(t, rf, func(tx *sql.Tx) error {
		return f.s.AcknowledgeHistoricalRotationCheckInTransaction(t.Context(), tx, rf.identity.Scope, rf.identity.ID, check.Task.Context.TaskID, check.KeyDigest, "console")
	}); err != nil {
		t.Fatal(err)
	}
	if err = historyGuard(t, rf); err != nil {
		t.Fatal("historical certificate prevented valid recovery", err)
	}
}

func TestHistoricalRotationAdmissionAuditFailureAndCapacityAreAtomic(t *testing.T) {
	f := newRotationFixture(t)
	rotation, wire := completedHistoricalRotation(t, f, "rotated")
	check, _ := historicalCheck(t, f, rotation, wire)
	queue := func() error {
		return historyTx(t, f, func(tx *sql.Tx) error {
			return f.s.QueueHistoricalRotationCheckInTransaction(t.Context(), tx, f.identity.Scope, f.identity.ID, check, "console")
		})
	}
	if _, err := f.s.db.Exec(`CREATE FUNCTION reject_history_admission_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='recovery.rotation.historical-check' THEN RAISE EXCEPTION 'synthetic admission audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_history_admission_audit BEFORE INSERT ON uem_agent_audit FOR EACH ROW EXECUTE FUNCTION reject_history_admission_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := queue(); err == nil {
		t.Fatal("audit failure admitted challenge")
	}
	var clean bool
	if err := f.s.db.QueryRow(`SELECT NOT EXISTS(SELECT 1 FROM uem_agent_recovery_tasks) AND NOT EXISTS(SELECT 1 FROM uem_agent_rotation_recovery_checks)`).Scan(&clean); err != nil || !clean {
		t.Fatal("admission audit failure left partial work", err)
	}
	if _, err := f.s.db.Exec(`DROP TRIGGER reject_history_admission_audit ON uem_agent_audit`); err != nil {
		t.Fatal(err)
	}
	if err := queue(); err != nil {
		t.Fatal("admission could not retry", err)
	}
	// The fixture fills the immutable ledger with synthetic cancelled rows.
	// Capacity counts all attempts, including unsuccessful ones, before any new
	// challenge can be delivered. Existing evidence is never overwritten.
	if _, err := f.s.db.Exec(`UPDATE uem_agent_recovery_tasks SET status='cancelled',envelope='\x',completed_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec(`WITH copies AS (INSERT INTO uem_agent_recovery_tasks(id,tenant_id,site_id,device_id,native_id,key_id,recipient_id,certificate_hash,nonce_hash,envelope,status,expires_at,completed_at) SELECT gen_random_uuid(),t.tenant_id,t.site_id,t.device_id,t.native_id,t.key_id,t.recipient_id,t.certificate_hash,t.nonce_hash,'\x','cancelled',t.expires_at,clock_timestamp() FROM uem_agent_recovery_tasks t CROSS JOIN generate_series(1,$1) RETURNING id,device_id) INSERT INTO uem_agent_rotation_recovery_checks(id,device_id,rotation_task_id,encrypted_record,created_at) SELECT c.id,c.device_id,h.rotation_task_id,h.encrypted_record,h.created_at FROM copies c CROSS JOIN uem_agent_rotation_recovery_checks h`, MaxHistoricalRotationChecks-1); err != nil {
		t.Fatal(err)
	}
	check, _ = historicalCheck(t, f, rotation, wire)
	if err := queue(); !errors.Is(err, ErrDenied) {
		t.Fatal("historical ledger overflow admitted work", err)
	}
	var count int
	if err := f.s.db.QueryRow(`SELECT count(*) FROM uem_agent_rotation_recovery_checks`).Scan(&count); err != nil || count != MaxHistoricalRotationChecks {
		t.Fatal("capacity changed retained history", err)
	}
}

func historicalCheck(t *testing.T, f *rotationFixture, rotation *enrollment.RotationTask, wire []byte) (HistoricalRotationCheck, []byte) {
	t.Helper()
	nonce := bytes.Repeat([]byte{9}, 32)
	c := enrollment.RecoveryContext{Version: 1, Identity: f.recipient.Identity, TaskID: uuid.NewString(), NativeID: rotation.Context.Binding.NativeID, KeyID: uuid.NewString(), RecipientID: f.recipient.ID, ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}
	task, err := enrollment.EncryptRecoveryTask(*f.recipient, c, []byte("1111-2222-3333-4444-5555-6666"), nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return HistoricalRotationCheck{RotationID: rotation.Context.Binding.TaskID, ReceiptHash: digest(wire), Task: *task, NonceHash: digest(nonce), KeyDigest: digest([]byte("synthetic encrypted retained key"))}, nonce
}

func historyTx(t *testing.T, f *rotationFixture, fn func(*sql.Tx) error) error {
	t.Helper()
	tx, err := f.s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func historyGuard(t *testing.T, f *rotationFixture) error {
	t.Helper()
	return historyTx(t, f, func(tx *sql.Tx) error {
		current, err := loadIdentityRenewalCurrent(t.Context(), tx, f.identity.ID)
		if err != nil {
			return err
		}
		return f.s.identityRenewalRotationGuard(t.Context(), tx, current)
	})
}

func reportHistoricalCheck(t *testing.T, f *rotationFixture, check HistoricalRotationCheck, nonce []byte, outcome string) {
	t.Helper()
	if _, err := f.access.HandleRecovery(t.Context(), *f.identity, enrollment.RecoveryRequest{Version: 1, AgentID: f.identity.ID, Action: "poll", RecipientID: f.recipient.ID}); err != nil {
		t.Fatal(err)
	}
	secret, err := f.agent.Open(check.Task, f.recipient.Identity, f.recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	result, err := secret.Result(outcome, f.cert, f.signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Nonce, nonce) {
		t.Fatal("wrong challenge delivered")
	}
	if _, err = f.access.HandleRecovery(t.Context(), *f.identity, enrollment.RecoveryRequest{Version: 1, AgentID: f.identity.ID, Action: "result", Result: result}); err != nil {
		t.Fatal(err)
	}
}

func TestHistoricalRotationFreshCheckRetainsProofAndReleasesGuard(t *testing.T) {
	f := newRotationFixture(t)
	rotation, wire := completedHistoricalRotation(t, f, "rotated")
	check, nonce := historicalCheck(t, f, rotation, wire)
	if err := historyGuard(t, f); !errors.Is(err, ErrRenewalRecoveryPending) {
		t.Fatal("historical return was released without key processing", err)
	}
	if err := historyTx(t, f, func(tx *sql.Tx) error {
		return f.s.QueueHistoricalRotationCheckInTransaction(t.Context(), tx, f.identity.Scope, f.identity.ID, check, "console")
	}); err != nil {
		t.Fatal(err)
	}
	ack := func(key string) error {
		return historyTx(t, f, func(tx *sql.Tx) error {
			return f.s.AcknowledgeHistoricalRotationCheckInTransaction(t.Context(), tx, f.identity.Scope, f.identity.ID, check.Task.Context.TaskID, key, "console")
		})
	}
	if err := ack(check.KeyDigest); !errors.Is(err, ErrDenied) {
		t.Fatal("pending proof accepted", err)
	}
	reportHistoricalCheck(t, f, check, nonce, "valid")
	if err := ack(digest([]byte("replacement ciphertext"))); !errors.Is(err, ErrDenied) {
		t.Fatal("different retained key accepted", err)
	}
	if err := historyGuard(t, f); !errors.Is(err, ErrRenewalRecoveryPending) {
		t.Fatal("worker proof alone released handoff", err)
	}
	for range 2 {
		if err := ack(check.KeyDigest); err != nil {
			t.Fatal("trusted reconciliation or exact retry failed", err)
		}
	}
	if err := historyGuard(t, f); err != nil {
		t.Fatal("valid historical proof did not release handoff", err)
	}
	var intact bool
	if err := f.s.db.QueryRow(`SELECT t.result=$2 AND (SELECT count(*) FROM uem_agent_rotation_reconciliations)=1 AND (SELECT count(*) FROM uem_agent_audit WHERE action='recovery.rotation.historically-reconciled')=1 FROM uem_agent_rotation_tasks t WHERE t.id=$1`, check.RotationID, wire).Scan(&intact); err != nil || !intact {
		t.Fatal("receipt changed or retry duplicated audit", err)
	}
	for _, statement := range []string{
		`UPDATE uem_agent_recovery_tasks SET result='\x' WHERE status='completed'`,
		`UPDATE uem_agent_recovery_tasks SET completed_at=completed_at+interval '1 second' WHERE status='completed'`,
		`UPDATE uem_agent_recovery_tasks SET nonce_hash=repeat('0',64)`,
		`UPDATE uem_agent_recovery_tasks SET recipient_id='00000000-0000-4000-8000-000000000001'`,
		`ALTER TABLE uem_agent_rotation_recovery_checks DISABLE TRIGGER uem_agent_rotation_recovery_check_immutable; UPDATE uem_agent_rotation_recovery_checks SET encrypted_record=set_byte(encrypted_record,20,get_byte(encrypted_record,20)#1)`,
		`ALTER TABLE uem_agent_rotation_recovery_checks DISABLE TRIGGER ALL; DELETE FROM uem_agent_rotation_recovery_checks; ALTER TABLE uem_agent_rotation_recovery_checks ENABLE TRIGGER ALL`,
		`ALTER TABLE uem_agent_rotation_reconciliations DISABLE TRIGGER uem_agent_rotation_reconciliation_immutable; UPDATE uem_agent_rotation_reconciliations SET recovery_check_id=NULL`,
	} {
		t.Run(statement, func(t *testing.T) {
			tx, err := f.s.db.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err = tx.ExecContext(t.Context(), statement); err != nil {
				t.Fatal(err)
			}
			current, err := loadIdentityRenewalCurrent(t.Context(), tx, f.identity.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.s.identityRenewalRotationGuard(t.Context(), tx, current); !errors.Is(err, ErrUnavailable) {
				t.Fatal("damaged historical evidence released handoff", err)
			}
		})
	}
	if err := historyGuard(t, f); err != nil {
		t.Fatal("restored complete history rejected", err)
	}
}

func TestHistoricalRotationRejectsUnboundAndUnsuccessfulChecks(t *testing.T) {
	for _, outcome := range []string{"valid", "invalid", "unavailable", "unsupported"} {
		t.Run(outcome, func(t *testing.T) {
			f := newRotationFixture(t)
			rotation, wire := completedHistoricalRotation(t, f, "unverified")
			check, nonce := historicalCheck(t, f, rotation, wire)
			err := historyTx(t, f, func(tx *sql.Tx) error {
				if outcome == "valid" {
					return f.access.QueueRecoveryTask(t.Context(), tx, check.Task, check.NonceHash)
				}
				return f.s.QueueHistoricalRotationCheckInTransaction(t.Context(), tx, f.identity.Scope, f.identity.ID, check, "console")
			})
			if err != nil {
				t.Fatal(err)
			}
			reportHistoricalCheck(t, f, check, nonce, outcome)
			if err = historyTx(t, f, func(tx *sql.Tx) error {
				return f.s.AcknowledgeHistoricalRotationCheckInTransaction(t.Context(), tx, f.identity.Scope, f.identity.ID, check.Task.Context.TaskID, check.KeyDigest, "console")
			}); !errors.Is(err, ErrDenied) {
				t.Fatal("unbound or unsuccessful proof accepted", err)
			}
			if err = historyGuard(t, f); !errors.Is(err, ErrRenewalRecoveryPending) {
				t.Fatal("guard lost pending history", err)
			}
		})
	}
}

func TestHistoricalRotationNonKeyOutcomesRequireExactReceipt(t *testing.T) {
	for _, outcome := range []string{"invalid", "unavailable", "unsupported", "rotated", "uncertain"} {
		t.Run(outcome, func(t *testing.T) {
			f := newRotationFixture(t)
			rotation, wire := completedHistoricalRotation(t, f, outcome)
			ack := func(hash string) error {
				return historyTx(t, f, func(tx *sql.Tx) error {
					return f.s.AcknowledgeHistoricalRotationWithoutKeyInTransaction(t.Context(), tx, f.identity.Scope, f.identity.ID, rotation.Context.Binding.NativeID, rotation.Context.Binding.TaskID, hash, "console")
				})
			}
			if err := ack(digest([]byte("different receipt"))); !errors.Is(err, ErrDenied) {
				t.Fatal("wrong receipt admitted", err)
			}
			err := ack(digest(wire))
			if outcome == "rotated" || outcome == "uncertain" {
				if !errors.Is(err, ErrDenied) {
					t.Fatal("mutation bypassed fresh check", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = ack(digest(wire)); err != nil {
				t.Fatal("exact retry failed", err)
			}
			if err = historyGuard(t, f); err != nil {
				t.Fatal("non-mutating receipt blocked renewal", err)
			}
		})
	}
}
