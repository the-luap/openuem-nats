package registry

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

func TestRotationResolutionRequiresStoppedExecutionAndSelectedValidProof(t *testing.T) {
	f := newRotationFixture(t)
	rotation := f.queue(t)
	nonce := bytes.Repeat([]byte{6}, 32)
	newProof := func() *enrollment.RecoveryTask {
		t.Helper()
		c := enrollment.RecoveryContext{Version: 1, Identity: f.recipient.Identity, TaskID: uuid.NewString(), NativeID: rotation.Context.Binding.NativeID, KeyID: uuid.NewString(), RecipientID: f.recipient.ID, ExpiresAt: time.Now().Add(time.Minute).Unix()}
		task, err := enrollment.EncryptRecoveryTask(*f.recipient, c, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), nonce, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return task
	}
	transaction := func(operation func(*sql.Tx) error, commit bool) error {
		t.Helper()
		tx, err := f.s.db.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err = operation(tx); err != nil {
			return err
		}
		if commit {
			return tx.Commit()
		}
		return nil
	}
	queue := func(task *enrollment.RecoveryTask, commit bool) error {
		return transaction(func(tx *sql.Tx) error {
			return f.access.QueueRotationValidation(t.Context(), tx, rotation.Context, *task, digest(nonce))
		}, commit)
	}
	resolve := func(task *enrollment.RecoveryTask) error {
		return transaction(func(tx *sql.Tx) error {
			return f.access.ResolveRotation(t.Context(), tx, rotation.Context, task.Context, digest(nonce), "admin")
		}, true)
	}
	proof := newProof()
	if err := queue(proof, true); !errors.Is(err, ErrDenied) {
		t.Fatal("undelivered mutation admitted resolution", err)
	}
	if _, err := f.access.HandleRotation(t.Context(), *f.identity, f.pollRequest()); err != nil {
		t.Fatal(err)
	}
	if err := queue(proof, true); !errors.Is(err, ErrDenied) {
		t.Fatal("running mutation admitted resolution", err)
	}
	// A timeout alone is not evidence that a process no longer owns its lease.
	if _, err := f.s.db.Exec(`UPDATE uem_agent_rotation_tasks SET status='uncertain',envelope='\x' WHERE id=$1`, rotation.Context.Binding.TaskID); err != nil {
		t.Fatal(err)
	}
	if err := queue(proof, true); !errors.Is(err, ErrDenied) {
		t.Fatal("receipt-free uncertainty admitted resolution", err)
	}
	uncertain := f.result(t, rotation.Context, "uncertain")
	if _, err := f.access.HandleRotation(t.Context(), *f.identity, uncertain); err != nil {
		t.Fatal(err)
	}
	f.cannotQueue(t)
	if err := queue(proof, false); err != nil {
		t.Fatal(err)
	}
	var clean bool
	if err := f.s.db.QueryRow(`SELECT resolution_task_id IS NULL AND NOT EXISTS(SELECT 1 FROM uem_agent_recovery_tasks WHERE id=$2) FROM uem_agent_rotation_tasks WHERE id=$1`, rotation.Context.Binding.TaskID, proof.Context.TaskID).Scan(&clean); err != nil || !clean {
		t.Fatal("proof queue escaped caller rollback", err)
	}
	if err := queue(proof, true); err != nil {
		t.Fatal("stopped execution denied read-only proof", err)
	}
	if err := resolve(proof); !errors.Is(err, ErrDenied) {
		t.Fatal("unfinished proof resolved rotation", err)
	}
	f.cannotQueue(t)
	report := func(task *enrollment.RecoveryTask, outcome string) {
		t.Helper()
		reply, err := f.access.HandleRecovery(t.Context(), *f.identity, enrollment.RecoveryRequest{Version: 1, AgentID: f.identity.ID, Action: "poll", RecipientID: f.recipient.ID})
		if err != nil || reply.Task == nil || reply.Task.Context != task.Context {
			t.Fatal("read-only proof delivery failed", err)
		}
		secret, err := f.agent.Open(*reply.Task, f.recipient.Identity, f.recipient.ID, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		result, err := secret.Result(outcome, f.cert, f.signer, time.Now())
		secret.Close()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.access.HandleRecovery(t.Context(), *f.identity, enrollment.RecoveryRequest{Version: 1, AgentID: f.identity.ID, Action: "result", Result: result}); err != nil {
			t.Fatal(err)
		}
	}
	report(proof, "invalid")
	if err := resolve(proof); !errors.Is(err, ErrDenied) {
		t.Fatal("invalid key resolved rotation", err)
	}
	second := newProof()
	if err := queue(second, true); err != nil {
		t.Fatal(err)
	}
	if err := resolve(proof); !errors.Is(err, ErrDenied) {
		t.Fatal("superseded proof resolved rotation", err)
	}
	report(second, "valid")
	var original []byte
	if err := f.s.db.QueryRow(`SELECT result FROM uem_agent_recovery_tasks WHERE id=$1`, second.Context.TaskID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	var forged enrollment.RecoveryResult
	if err := json.Unmarshal(original, &forged); err != nil {
		t.Fatal(err)
	}
	forged.Context.KeyID = uuid.NewString()
	changed, _ := json.Marshal(forged)
	if _, err := f.s.db.Exec(`UPDATE uem_agent_recovery_tasks SET result=$2 WHERE id=$1`, second.Context.TaskID, changed); err != nil {
		t.Fatal(err)
	}
	if err := resolve(second); !errors.Is(err, ErrDenied) {
		t.Fatal("changed proof context resolved rotation", err)
	}
	if _, err := f.s.db.Exec(`UPDATE uem_agent_recovery_tasks SET result=$2 WHERE id=$1`, second.Context.TaskID, original); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_audit ADD CONSTRAINT resolution_audit_failure CHECK(action!='recovery.rotation.resolved')`); err != nil {
		t.Fatal(err)
	}
	if err := resolve(second); err == nil {
		t.Fatal("resolution escaped audit failure")
	}
	f.state(t, rotation.Context.Binding.TaskID, "uncertain", false)
	if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_audit DROP CONSTRAINT resolution_audit_failure`); err != nil {
		t.Fatal(err)
	}
	if err := resolve(second); err != nil {
		t.Fatal("valid selected proof denied", err)
	}
	f.state(t, rotation.Context.Binding.TaskID, "completed", false)
	var retained bool
	wire, _ := json.Marshal(uncertain.Result)
	if err := f.s.db.QueryRow(`SELECT resolved_at IS NOT NULL AND result=$2 AND resolution_task_id=$3 FROM uem_agent_rotation_tasks WHERE id=$1`, rotation.Context.Binding.TaskID, wire, second.Context.TaskID).Scan(&retained); err != nil || !retained {
		t.Fatal("resolution discarded immutable evidence", err)
	}
	if _, err := f.access.HandleRotation(t.Context(), *f.identity, uncertain); err != nil {
		t.Fatal("resolution denied identical lost acknowledgment", err)
	}
	if err := resolve(second); !errors.Is(err, ErrDenied) {
		t.Fatal("resolved proof reused", err)
	}
	if next := f.queue(t); next.Context.Ordinal != 2 {
		t.Fatal("resolution reused mutation ordinal")
	}
}

func TestRotationResolutionRejectsAlteredStopEvidence(t *testing.T) {
	f := newRotationFixture(t)
	rotation := f.queue(t)
	if _, err := f.access.HandleRotation(t.Context(), *f.identity, f.pollRequest()); err != nil {
		t.Fatal(err)
	}
	request := f.result(t, rotation.Context, "uncertain")
	if _, err := f.access.HandleRotation(t.Context(), *f.identity, request); err != nil {
		t.Fatal(err)
	}
	proof := rotation.Context.Binding
	proof.TaskID, proof.ExpiresAt = uuid.NewString(), time.Now().Add(time.Minute).Unix()
	task, err := enrollment.EncryptRecoveryTask(*f.recipient, proof, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), f.nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*enrollment.RotationResult){
		func(r *enrollment.RotationResult) { r.Context.EscrowID = uuid.NewString() },
		func(r *enrollment.RotationResult) { r.Nonce = bytes.Repeat([]byte{9}, 32) },
		func(r *enrollment.RotationResult) { r.Signature[0] ^= 1 },
	} {
		original, _ := json.Marshal(request.Result)
		var invalid enrollment.RotationResult
		if json.Unmarshal(original, &invalid) != nil {
			t.Fatal("fixture decode failed")
		}
		alter(&invalid)
		wire, _ := json.Marshal(invalid)
		if _, err = f.s.db.Exec(`UPDATE uem_agent_rotation_tasks SET result=$2 WHERE id=$1`, rotation.Context.Binding.TaskID, wire); err != nil {
			t.Fatal(err)
		}
		tx, err := f.s.db.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		err = f.access.QueueRotationValidation(t.Context(), tx, rotation.Context, *task, digest(f.nonce))
		tx.Rollback()
		if !errors.Is(err, ErrDenied) {
			t.Fatal("altered stop evidence admitted proof", err)
		}
	}
}
