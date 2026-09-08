package registry

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

type rotationFixture struct {
	s         *Store
	access    *AccessStore
	identity  *Identity
	cert      *x509.Certificate
	signer    *rsa.PrivateKey
	agent     *enrollment.RecoveryRecipientKey
	console   *enrollment.RecoveryRecipientKey
	recipient *enrollment.RecoveryRecipient
	nonce     []byte
}

func newRotationFixture(t *testing.T) *rotationFixture {
	t.Helper()
	f := &rotationFixture{s: testStore(t), nonce: bytes.Repeat([]byte{8}, 32)}
	f.access, f.identity, f.cert, f.signer = testRecoveryAgent(t, f.s)
	var err error
	f.agent, err = enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.agent.Close)
	f.console, err = enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.console.Close)
	f.recipient, _, _ = testRegisterRecovery(t, f.access, f.identity, f.cert, f.signer, f.agent)
	return f
}

func (f *rotationFixture) queue(t *testing.T) *enrollment.RotationTask {
	t.Helper()
	tx, err := f.s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	ordinal, err := f.access.NextRotationOrdinal(t.Context(), tx, f.identity.Scope, f.identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	c := enrollment.RotationContext{Binding: enrollment.RecoveryContext{Version: 1, Identity: f.recipient.Identity, TaskID: uuid.NewString(), NativeID: uuid.NewString(), KeyID: uuid.NewString(), RecipientID: f.recipient.ID, ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}, Ordinal: ordinal, EscrowID: uuid.NewString(), ReplyKey: hex.EncodeToString(f.console.PublicKey())}
	task, err := enrollment.EncryptRotationTask(*f.recipient, c, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), f.nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = f.access.QueueRotationTask(t.Context(), tx, *task, digest(f.nonce)); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return task
}

func (f *rotationFixture) pollRequest() enrollment.RotationRequest {
	return enrollment.RotationRequest{Version: enrollment.RotationVersion, Protocol: enrollment.RotationProtocol, AgentID: f.identity.ID, Action: "poll", RecipientID: f.recipient.ID}
}

func (f *rotationFixture) result(t *testing.T, c enrollment.RotationContext, outcome string) enrollment.RotationRequest {
	t.Helper()
	var key []byte
	if outcome == "rotated" || outcome == "unverified" {
		key = []byte("1111-2222-3333-4444-5555-6666")
	}
	r, err := enrollment.NewRotationResult(c, outcome, f.nonce, key, f.cert, f.signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return enrollment.RotationRequest{Version: enrollment.RotationVersion, Protocol: enrollment.RotationProtocol, AgentID: f.identity.ID, Action: "result", Result: r}
}

func (f *rotationFixture) state(t *testing.T, id, status string, retained bool) {
	t.Helper()
	var correct bool
	if err := f.s.db.QueryRow(`SELECT status=$2 AND (octet_length(envelope)>0)=$3 FROM uem_agent_rotation_tasks WHERE id=$1`, id, status, retained).Scan(&correct); err != nil || !correct {
		t.Fatal("incorrect rotation state or request retention", status, err)
	}
}

func (f *rotationFixture) cannotQueue(t *testing.T) {
	t.Helper()
	tx, err := f.s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = f.access.NextRotationOrdinal(t.Context(), tx, f.identity.Scope, f.identity.ID); !errors.Is(err, ErrDenied) {
		t.Fatal("unresolved rotation admitted another attempt", err)
	}
	c := enrollment.RecoveryContext{Version: 1, Identity: f.recipient.Identity, TaskID: uuid.NewString(), NativeID: uuid.NewString(), KeyID: uuid.NewString(), RecipientID: f.recipient.ID, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	task, err := enrollment.EncryptRecoveryTask(*f.recipient, c, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), f.nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = f.access.QueueRecoveryTask(t.Context(), tx, *task, digest(f.nonce)); !errors.Is(err, ErrDenied) {
		t.Fatal("unresolved rotation admitted old-key validation", err)
	}
}

func TestRotationDeliveryEncryptedReceiptAndAtomicAudit(t *testing.T) {
	f := newRotationFixture(t)
	if !f.access.RotationReady(t.Context()) {
		t.Fatal("rotation migration is not ready")
	}
	validation := testQueueRecovery(t, f.s, f.access, f.identity, f.recipient)
	task := f.queue(t)
	var cancelled bool
	if err := f.s.db.QueryRow(`SELECT status='cancelled' AND octet_length(envelope)=0 FROM uem_agent_recovery_tasks WHERE id=$1`, validation.Context.TaskID).Scan(&cancelled); err != nil || !cancelled {
		t.Fatal("rotation left an old-key validation pending", err)
	}
	f.cannotQueue(t)
	request := f.result(t, task.Context, "rotated")
	if _, err := f.access.HandleRotation(t.Context(), *f.identity, request); !errors.Is(err, ErrDenied) {
		t.Fatal("undelivered result accepted", err)
	}
	reply, err := f.access.HandleRotation(t.Context(), *f.identity, f.pollRequest())
	if err != nil || reply.Task == nil || reply.Task.Context != task.Context {
		t.Fatal("wrong rotation task delivered", err)
	}
	secret, err := f.agent.OpenRotationTask(*reply.Task, f.recipient.Identity, f.recipient.ID, time.Now())
	if err != nil || !bytes.Equal(secret.Key(), []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")) {
		t.Fatal("endpoint could not decrypt task", err)
	}
	secret.Close()
	var delivered time.Time
	if err = f.s.db.QueryRow(`SELECT delivered_at FROM uem_agent_rotation_tasks WHERE id=$1`, task.Context.Binding.TaskID).Scan(&delivered); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errorsByPoll := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			_, err := f.access.HandleRotation(t.Context(), *f.identity, f.pollRequest())
			errorsByPoll <- err
		})
	}
	wg.Wait()
	close(errorsByPoll)
	for err := range errorsByPoll {
		if err != nil {
			t.Fatal(err)
		}
	}
	var unchanged bool
	if err = f.s.db.QueryRow(`SELECT delivered_at=$2 FROM uem_agent_rotation_tasks WHERE id=$1`, task.Context.Binding.TaskID, delivered).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("retry changed the original delivery time", err)
	}
	if _, err = f.s.db.Exec(`ALTER TABLE uem_agent_audit ADD CONSTRAINT rotation_audit_failure CHECK(action!='recovery.rotation.reported')`); err != nil {
		t.Fatal(err)
	}
	if _, err = f.access.HandleRotation(t.Context(), *f.identity, request); err == nil {
		t.Fatal("rotation receipt committed without audit")
	}
	f.state(t, task.Context.Binding.TaskID, "pending", true)
	if err = f.s.db.QueryRow(`SELECT result IS NULL FROM uem_agent_rotation_tasks WHERE id=$1`, task.Context.Binding.TaskID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("failed audit retained the receipt", err)
	}
	if _, err = f.s.db.Exec(`ALTER TABLE uem_agent_audit DROP CONSTRAINT rotation_audit_failure`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err = f.access.HandleRotation(t.Context(), *f.identity, request); err != nil {
			t.Fatal("authentic receipt or retry rejected", err)
		}
	}
	f.state(t, task.Context.Binding.TaskID, "completed", false)
	var stored []byte
	if err = f.s.db.QueryRow(`SELECT result FROM uem_agent_rotation_tasks WHERE id=$1`, task.Context.Binding.TaskID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	var result enrollment.RotationResult
	if json.Unmarshal(stored, &result) != nil {
		t.Fatal("stored receipt is invalid")
	}
	returned, err := f.console.OpenRotationResult(result, task.Context, digest(f.nonce), f.cert, time.Now())
	if err != nil || !bytes.Equal(returned.Key(), []byte("1111-2222-3333-4444-5555-6666")) {
		t.Fatal("console could not recover the new key", err)
	}
	returned.Close()
	var count int
	if err = f.s.db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE action='recovery.rotation.reported'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("retry inflated audit", count, err)
	}
	conflict := f.result(t, task.Context, "invalid")
	if _, err = f.access.HandleRotation(t.Context(), *f.identity, conflict); !errors.Is(err, ErrDenied) {
		t.Fatal("immutable receipt replaced", err)
	}
	reply, err = f.access.HandleRotation(t.Context(), *f.identity, f.pollRequest())
	if err != nil || reply.Task != nil || reply.Receipt != nil {
		t.Fatal("completed rotation redelivered", err)
	}
	if next := f.queue(t); next.Context.Ordinal != 2 {
		t.Fatal("attempt ordinal reused")
	}
	var document []byte
	if err = f.s.db.QueryRow(`SELECT json_agg(t)::text FROM uem_agent_rotation_tasks t`).Scan(&document); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(document, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")) || bytes.Contains(document, []byte("1111-2222-3333-4444-5555-6666")) {
		t.Fatal("routing database contains a plaintext key")
	}
}

// Backdate the independently stored expectation as well as its context. This
// exercises database-clock expiry without sleeping or invoking any device.
func (f *rotationFixture) backdate(t *testing.T, task *enrollment.RotationTask, delivered bool) {
	t.Helper()
	task.Context.Binding.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	bound, _ := json.Marshal(task.Context)
	if _, err := f.s.db.Exec(`UPDATE uem_agent_rotation_tasks SET context=$2,expires_at=to_timestamp($3),created_at=to_timestamp($3)-interval '2 minutes',delivered_at=CASE WHEN $4 THEN to_timestamp($3)-interval '1 minute' ELSE NULL END WHERE id=$1`, task.Context.Binding.TaskID, bound, task.Context.Binding.ExpiresAt, delivered); err != nil {
		t.Fatal(err)
	}
}

func TestRotationExpiryRetainsUncertaintyAndAcceptsLateKeys(t *testing.T) {
	for _, delivered := range []bool{false, true} {
		t.Run(map[bool]string{false: "undelivered", true: "delivered"}[delivered], func(t *testing.T) {
			f := newRotationFixture(t)
			task := f.queue(t)
			f.backdate(t, task, delivered)
			if err := f.access.ExpireRotationTasks(t.Context()); err != nil {
				t.Fatal(err)
			}
			if !delivered {
				f.state(t, task.Context.Binding.TaskID, "expired", false)
				if _, err := f.access.HandleRotation(t.Context(), *f.identity, f.result(t, task.Context, "rotated")); !errors.Is(err, ErrDenied) {
					t.Fatal("expired undelivered task accepted a key", err)
				}
				if next := f.queue(t); next.Context.Ordinal != 2 {
					t.Fatal("expired attempt reused its slot")
				}
				return
			}
			f.state(t, task.Context.Binding.TaskID, "uncertain", false)
			f.cannotQueue(t)
			reply, err := f.access.HandleRotation(t.Context(), *f.identity, f.pollRequest())
			if err != nil || reply.Task != nil || reply.Receipt == nil || *reply.Receipt != task.Context {
				t.Fatal("uncertain poll did not request the cached receipt", err)
			}
			if _, err = f.access.HandleRotation(t.Context(), *f.identity, f.result(t, task.Context, "rotated")); err != nil {
				t.Fatal("authentic late key was lost", err)
			}
			f.state(t, task.Context.Binding.TaskID, "completed", false)
		})
	}
}

func TestRotationSignedUncertaintyDoesNotAuthorizeAnotherMutation(t *testing.T) {
	f := newRotationFixture(t)
	task := f.queue(t)
	if _, err := f.access.HandleRotation(t.Context(), *f.identity, f.pollRequest()); err != nil {
		t.Fatal(err)
	}
	request := f.result(t, task.Context, "uncertain")
	for range 2 {
		if _, err := f.access.HandleRotation(t.Context(), *f.identity, request); err != nil {
			t.Fatal(err)
		}
	}
	f.state(t, task.Context.Binding.TaskID, "uncertain", false)
	f.cannotQueue(t)
	if _, err := f.access.HandleRotation(t.Context(), *f.identity, f.result(t, task.Context, "invalid")); !errors.Is(err, ErrDenied) {
		t.Fatal("conflicting receipt resolved uncertainty", err)
	}
	var count int
	if err := f.s.db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE action='recovery.rotation.reported'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("uncertain retry inflated audit", count, err)
	}
	if _, err := f.s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := f.access.ExpireRotationTasks(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec(`UPDATE sites SET tenant_sites=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.access.HandleRotation(t.Context(), *f.identity, request); !errors.Is(err, ErrDenied) {
		t.Fatal("restored scope revived a cancelled receipt", err)
	}
}

func TestRotationIndependentlyChecksContextNonceAndAuthority(t *testing.T) {
	f := newRotationFixture(t)
	task := f.queue(t)
	if _, err := f.access.HandleRotation(t.Context(), *f.identity, f.pollRequest()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*enrollment.RotationContext){
		"native":     func(c *enrollment.RotationContext) { c.Binding.NativeID = uuid.NewString() },
		"source key": func(c *enrollment.RotationContext) { c.Binding.KeyID = uuid.NewString() },
		"task":       func(c *enrollment.RotationContext) { c.Binding.TaskID = uuid.NewString() },
		"recipient":  func(c *enrollment.RotationContext) { c.Binding.RecipientID = uuid.NewString() },
		"ordinal":    func(c *enrollment.RotationContext) { c.Ordinal++ },
		"escrow":     func(c *enrollment.RotationContext) { c.EscrowID = uuid.NewString() },
		"deadline":   func(c *enrollment.RotationContext) { c.Binding.ExpiresAt++ },
		"reply key":  func(c *enrollment.RotationContext) { c.ReplyKey = hex.EncodeToString(f.agent.PublicKey()) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := task.Context
			mutate(&changed)
			if _, err := f.access.HandleRotation(t.Context(), *f.identity, f.result(t, changed, "invalid")); !errors.Is(err, ErrDenied) {
				t.Fatal("authentic but unrelated context accepted", err)
			}
		})
	}
	f.nonce[0] ^= 1
	if _, err := f.access.HandleRotation(t.Context(), *f.identity, f.result(t, task.Context, "invalid")); !errors.Is(err, ErrDenied) {
		t.Fatal("authentic but unrelated nonce accepted", err)
	}
	f.nonce[0] ^= 1
	for _, mutate := range []func(*Identity){func(i *Identity) { i.SiteID = 2 }, func(i *Identity) { i.TenantID = 2 }, func(i *Identity) { i.Platform = "windows" }} {
		wrong := *f.identity
		mutate(&wrong)
		if _, err := f.access.HandleRotation(t.Context(), wrong, f.pollRequest()); !errors.Is(err, ErrDenied) {
			t.Fatal("foreign authority polled rotation", err)
		}
	}
	wrong := f.pollRequest()
	wrong.AgentID = uuid.NewString()
	if _, err := f.access.HandleRotation(t.Context(), *f.identity, wrong); !errors.Is(err, ErrDenied) {
		t.Fatal("body identity mismatch accepted", err)
	}
	second, err := enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	newRecipient, _, _ := testRegisterRecovery(t, f.access, f.identity, f.cert, f.signer, second)
	f.state(t, task.Context.Binding.TaskID, "cancelled", false)
	if _, err = f.access.HandleRotation(t.Context(), *f.identity, f.result(t, task.Context, "rotated")); !errors.Is(err, ErrDenied) {
		t.Fatal("retired recipient returned a key", err)
	}
	f.recipient = newRecipient
	next := f.queue(t)
	if next.Context.Ordinal != 2 {
		t.Fatal("recipient replacement reused an attempt slot")
	}
	if err = f.s.RevokeIdentity(t.Context(), f.identity.Scope, f.identity.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	f.state(t, next.Context.Binding.TaskID, "cancelled", false)
	if _, err = f.access.HandleRotation(t.Context(), *f.identity, f.pollRequest()); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked identity polled rotation", err)
	}
}

func TestRotationNeverReusesSlotsAndRequiresSufficientCertificateLifetime(t *testing.T) {
	f := newRotationFixture(t)
	task := f.queue(t)
	if _, err := f.s.db.Exec(`UPDATE uem_agent_rotation_tasks SET status='cancelled',envelope='\x',ordinal=127 WHERE id=$1`, task.Context.Binding.TaskID); err != nil {
		t.Fatal(err)
	}
	last := f.queue(t)
	if last.Context.Ordinal != enrollment.MaxRotationAttempts {
		t.Fatal("last slot not allocated monotonically")
	}
	if _, err := f.s.db.Exec(`UPDATE uem_agent_rotation_tasks SET status='cancelled',envelope='\x' WHERE id=$1`, last.Context.Binding.TaskID); err != nil {
		t.Fatal(err)
	}
	tx, err := f.s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = f.access.NextRotationOrdinal(t.Context(), tx, f.identity.Scope, f.identity.ID); !errors.Is(err, ErrDenied) {
		t.Fatal("agent lifetime attempt limit bypassed", err)
	}
	tx.Rollback()

	f = newRotationFixture(t)
	task = f.queue(t)
	if _, err = f.s.db.Exec(`UPDATE uem_agent_rotation_tasks SET status='cancelled',envelope='\x' WHERE id=$1;`, task.Context.Binding.TaskID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.db.Exec(`UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()+interval '30 seconds' WHERE id=$1`, f.identity.ID); err != nil {
		t.Fatal(err)
	}
	task.Context.Ordinal++
	task.Context.Binding.TaskID = uuid.NewString()
	tx, err = f.s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = f.access.QueueRotationTask(t.Context(), tx, *task, digest(f.nonce)); !errors.Is(err, ErrDenied) {
		t.Fatal("task exceeded the current database certificate lifetime", err)
	}
}

func TestRotationExpiryDuringIdentityAndTaskLockWaits(t *testing.T) {
	for _, lock := range []string{"identity", "task"} {
		for _, action := range []string{"poll", "result"} {
			t.Run(lock+"/"+action, func(t *testing.T) {
				f := newRotationFixture(t)
				task := f.queue(t)
				if _, err := f.access.HandleRotation(t.Context(), *f.identity, f.pollRequest()); err != nil {
					t.Fatal(err)
				}
				request := f.pollRequest()
				if action == "result" {
					request = f.result(t, task.Context, "rotated")
				}
				if _, err := f.s.db.Exec(`UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()+interval '200 milliseconds' WHERE id=$1`, f.identity.ID); err != nil {
					t.Fatal(err)
				}
				tx, err := f.s.db.BeginTx(t.Context(), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				query, id := `SELECT id FROM uem_agent_identities WHERE id=$1 FOR UPDATE`, f.identity.ID
				if lock == "task" {
					query, id = `SELECT id FROM uem_agent_rotation_tasks WHERE id=$1 FOR UPDATE`, task.Context.Binding.TaskID
				}
				var locked string
				if err = tx.QueryRow(query, id).Scan(&locked); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { _, err := f.access.HandleRotation(t.Context(), *f.identity, request); done <- err }()
				time.Sleep(250 * time.Millisecond)
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
				if err = <-done; !errors.Is(err, ErrDenied) {
					t.Fatal("certificate expiry during row lock wait was ignored", err)
				}
				if err = f.access.ExpireRotationTasks(t.Context()); err != nil {
					t.Fatal(err)
				}
				f.state(t, task.Context.Binding.TaskID, "cancelled", false)
			})
		}
	}
}

func TestRotationQueueReservesTimeForDurableReceiptPublication(t *testing.T) {
	f := newRotationFixture(t)
	template := f.queue(t)
	if _, err := f.s.db.Exec(`UPDATE uem_agent_rotation_tasks SET status='cancelled',envelope='\x' WHERE id=$1`, template.Context.Binding.TaskID); err != nil {
		t.Fatal(err)
	}
	c := template.Context
	c.Ordinal++
	c.Binding.TaskID = uuid.NewString()
	c.Binding.ExpiresAt = time.Now().Add(time.Minute).Unix()
	task, err := enrollment.EncryptRotationTask(*f.recipient, c, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), f.nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, seconds := range []int64{int64(enrollment.RotationReceiptGrace/time.Second) - 1, int64(enrollment.RotationReceiptGrace / time.Second)} {
		if _, err = f.s.db.Exec(`UPDATE uem_agent_identities SET certificate_expires_at=to_timestamp($2) WHERE id=$1`, f.identity.ID, c.Binding.ExpiresAt+seconds); err != nil {
			t.Fatal(err)
		}
		tx, err := f.s.db.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		err = f.access.QueueRotationTask(t.Context(), tx, *task, digest(f.nonce))
		if seconds < int64(enrollment.RotationReceiptGrace/time.Second) {
			tx.Rollback()
			if !errors.Is(err, ErrDenied) {
				t.Fatal("rotation consumed its receipt-publication reserve", err)
			}
		} else {
			if err != nil {
				tx.Rollback()
				t.Fatal("sufficient publication reserve rejected", err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestRotationMaintenanceBoundsSkipsLockedAndDoesNotStarve(t *testing.T) {
	f := newRotationFixture(t)
	completed := f.queue(t)
	if _, err := f.access.HandleRotation(t.Context(), *f.identity, f.pollRequest()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.access.HandleRotation(t.Context(), *f.identity, f.result(t, completed.Context, "rotated")); err != nil {
		t.Fatal(err)
	}
	// Maintenance uses database authority bindings, not certificate issuance.
	// Synthetic clones keep this 514-device scheduling test fast and isolated;
	// none can authenticate through the certificate-verifying request handler.
	if _, err := f.s.db.Exec(`INSERT INTO uem_agent_identities(id,tenant_id,site_id,invitation_id,key_binding,certificate_key_hash,broker_key,platform,architecture,display_name,public_origin,certificate,authority_certificate,certificate_hash,certificate_expires_at)
 SELECT gen_random_uuid(),tenant_id,site_id,invitation_id,'rotation-maintenance-'||g,repeat(md5('key-'||g),2),'rotation-broker-'||g,platform,architecture,'Maintenance fixture '||g,public_origin,certificate,authority_certificate,repeat(md5('cert-'||g),2),certificate_expires_at
 FROM uem_agent_identities CROSS JOIN generate_series(1,514) g WHERE id=$1`, f.identity.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec(`INSERT INTO uem_agent_recovery_recipients(device_id,tenant_id,site_id,id,certificate_hash,public_key)
 SELECT id,tenant_id,site_id,gen_random_uuid(),certificate_hash,$1 FROM uem_agent_identities WHERE id!=$2`, f.agent.PublicKey(), f.identity.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec(`INSERT INTO uem_agent_rotation_tasks(id,tenant_id,site_id,device_id,ordinal,native_id,key_id,recipient_id,certificate_hash,nonce_hash,context,envelope,status,created_at,expires_at,delivered_at)
 SELECT gen_random_uuid(),i.tenant_id,i.site_id,i.id,1,gen_random_uuid(),gen_random_uuid(),r.id,i.certificate_hash,$1,'{}',
 CASE WHEN substring(i.key_binding FROM 22)::int<=256 THEN '\x'::bytea ELSE '\x01'::bytea END,
 CASE WHEN substring(i.key_binding FROM 22)::int<=256 THEN 'uncertain' ELSE 'pending' END,
 clock_timestamp()-interval '3 hours',clock_timestamp()-interval '2 hours'+substring(i.key_binding FROM 22)::int*interval '1 millisecond',
 CASE WHEN substring(i.key_binding FROM 22)::int<=256 THEN clock_timestamp()-interval '150 minutes' ELSE NULL END
 FROM uem_agent_identities i JOIN uem_agent_recovery_recipients r ON r.device_id=i.id WHERE i.id!=$2`, digest(f.nonce), f.identity.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := f.s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var locked string
	if err = tx.QueryRow(`SELECT id FROM uem_agent_rotation_tasks WHERE status='pending' ORDER BY expires_at,id LIMIT 1 FOR UPDATE`).Scan(&locked); err != nil {
		t.Fatal(err)
	}
	checkCounts := func(expired, pending int) {
		t.Helper()
		var actualExpired, actualPending, uncertain int
		if err := f.s.db.QueryRow(`SELECT count(*) FILTER(WHERE status='expired'),count(*) FILTER(WHERE status='pending'),count(*) FILTER(WHERE status='uncertain') FROM uem_agent_rotation_tasks`).Scan(&actualExpired, &actualPending, &uncertain); err != nil || actualExpired != expired || actualPending != pending || uncertain != 256 {
			t.Fatal("incorrect maintenance batch or uncertainty starvation", actualExpired, actualPending, uncertain, err)
		}
	}
	for pass := range 2 {
		if err = f.access.ExpireRotationTasks(t.Context()); err != nil {
			t.Fatal(err)
		}
		checkCounts(256+pass, 2-pass)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = f.access.ExpireRotationTasks(t.Context()); err != nil {
		t.Fatal(err)
	}
	checkCounts(258, 0)
	f.state(t, locked, "expired", false)
	// Changed site ownership invalidates unresolved requests, while previously
	// committed encrypted key receipts remain available to their owning console.
	if _, err = f.s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err = f.access.ExpireRotationTasks(t.Context()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = f.s.db.QueryRow(`SELECT count(*) FROM uem_agent_rotation_tasks WHERE status='cancelled' AND octet_length(envelope)=0`).Scan(&count); err != nil || count != 256 {
		t.Fatal("stale authority retained unresolved rotation", count, err)
	}
	var retained bool
	if err = f.s.db.QueryRow(`SELECT status='completed' AND result IS NOT NULL FROM uem_agent_rotation_tasks WHERE id=$1`, completed.Context.Binding.TaskID).Scan(&retained); err != nil || !retained {
		t.Fatal("maintenance erased a completed encrypted key receipt", err)
	}
}
