package registry

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

type softwareFixture struct {
	store           *Store
	access          *AccessStore
	identity        *Identity
	cert, authority *x509.Certificate
	signer          *rsa.PrivateKey
	key             *enrollment.SoftwareRecipientKey
	recipient       *enrollment.SoftwareRecipient
}

func softwarePlan() enrollment.SoftwarePlan {
	return enrollment.SoftwarePlan{Kind: "windows-msi", Operation: "install", Identifier: "Owned.RegistryFixture", Version: "1.2.3", Architecture: "amd64", MinimumOS: "10.0.26100", Artifact: enrollment.SoftwareArtifact{URL: "https://packages.example.test/owned.msi?token=private-source", SHA256: strings.Repeat("a", 64), Format: "msi"}, MSIProperties: map[string]string{"LICENSEKEY": "private-license"}, Detection: enrollment.SoftwareDetection{Kind: "msi-product", ProductCode: "{AABBCCDD-0000-4000-8000-000000000001}", Version: "1.2.3"}, SuccessCodes: []uint32{0}, RebootCodes: []uint32{3010}}
}
func newSoftwareFixture(t *testing.T) *softwareFixture {
	t.Helper()
	s := testStore(t)
	_, token := invite(t, s, Scope{TenantID: 1, SiteID: 1}, 1)
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Broker.Wipe)
	response, err := s.Claim(t.Context(), *proof(t, token, keys))
	if err != nil {
		t.Fatal(err)
	}
	access, err := NewAccessStore(s.db)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := access.ActiveIdentity(t.Context(), response.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := softwareCertificate([]byte(response.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	authority, err := softwareCertificate([]byte(response.Authority))
	if err != nil {
		t.Fatal(err)
	}
	key, err := enrollment.NewSoftwareRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Close)
	f := &softwareFixture{store: s, access: access, identity: identity, cert: cert, authority: authority, signer: keys.Certificate, key: key}
	f.register(t)
	return f
}
func (f *softwareFixture) call(ctx context.Context, request enrollment.SoftwareRequest) (*enrollment.SoftwareReply, error) {
	request.Version, request.Protocol = enrollment.SoftwareVersion, enrollment.SoftwareProtocol
	if request.AgentID == "" {
		request.AgentID = f.identity.ID
	}
	tx, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	reply, err := f.access.HandleSoftwareInTransaction(ctx, tx, *f.identity, request)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return reply, nil
}
func (f *softwareFixture) register(t *testing.T) {
	t.Helper()
	reply, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "challenge", PublicKey: f.key.PublicKey()})
	if err != nil || reply.Registration == nil {
		t.Fatal("software challenge", err)
	}
	signature, err := enrollment.SignSoftwareRegistration(*reply.Registration, f.cert, f.signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	reply, err = f.call(t.Context(), enrollment.SoftwareRequest{Action: "register", Registration: reply.Registration, Signature: signature})
	if err != nil || reply.Recipient == nil {
		t.Fatal("software registration", err)
	}
	f.recipient = reply.Recipient
}
func (f *softwareFixture) queue(t *testing.T) *enrollment.SoftwareTask {
	t.Helper()
	tx, err := f.store.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	task, err := f.store.QueueSoftwareTaskInTransaction(t.Context(), tx, f.identity.Scope, f.identity.ID, uuid.NewString(), uuid.NewString(), uuid.NewString(), softwarePlan(), time.Now().Add(5*time.Minute), "operator")
	if err != nil {
		t.Fatal("queue signed software", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return task
}
func (f *softwareFixture) result(t *testing.T, task *enrollment.SoftwareTask, state string) *enrollment.SoftwareResult {
	t.Helper()
	secret, err := f.key.Open(*task, f.authority, f.recipient.Identity, f.recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	zero := uint32(0)
	outcome := enrollment.SoftwareOutcome{State: "observed", Execution: "started", ExitCode: &zero, Before: enrollment.SoftwareObservation{State: "absent"}, After: enrollment.SoftwareObservation{State: "present", Version: "1.2.3"}}
	if state == "uncertain" {
		outcome = enrollment.SoftwareOutcome{State: "uncertain", Execution: "unknown", Before: enrollment.SoftwareObservation{State: "unknown"}, After: enrollment.SoftwareObservation{State: "unknown"}, Error: "interrupted"}
	}
	if state == "restart_required" {
		code := uint32(3010)
		outcome.State = state
		outcome.ExitCode = &code
	}
	result, err := enrollment.SignSoftwareResult(task.Context, f.recipient.Identity, secret.TaskHash(), secret.Nonce(), outcome, f.cert, f.signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func (f *softwareFixture) submit(t *testing.T, result *enrollment.SoftwareResult) (*enrollment.SoftwareReply, error) {
	t.Helper()
	tx, err := f.store.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	current, _, _, err := f.access.SoftwareIdentity(t.Context(), tx, f.identity.Scope, f.identity.ID)
	_ = tx.Rollback()
	if err != nil {
		return nil, err
	}
	proof, err := enrollment.SignSoftwareSubmission(*result, current, f.cert, f.signer, time.Now())
	if err != nil {
		return nil, err
	}
	return f.call(t.Context(), enrollment.SoftwareRequest{Action: "result", Result: result, Submission: proof})
}
func TestSoftwareTaskRegistryAuthenticatesDeliveryAndExactReceipts(t *testing.T) {
	f := newSoftwareFixture(t)
	task := f.queue(t)
	var envelope []byte
	if err := f.store.db.QueryRow(`SELECT envelope FROM uem_agent_software_tasks WHERE id=$1`, task.Context.TaskID).Scan(&envelope); err != nil || bytes.Contains(envelope, []byte("private-")) {
		t.Fatal("plaintext task storage", err)
	}
	result := f.result(t, task, "observed")
	if _, err := f.submit(t, result); err == nil {
		t.Fatal("result accepted before authenticated delivery")
	}
	reply, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID})
	if err != nil || reply.Task == nil || !reply.Task.Context.Equal(task.Context) {
		t.Fatal("poll did not return exact task", err)
	}
	for range 2 {
		reply, err = f.submit(t, result)
		if err != nil || reply.Receipt == nil || reply.Receipt.TaskID != task.Context.TaskID {
			t.Fatal("durable receipt/retry", err)
		}
	}
	var audits int
	if err = f.store.db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE resource_id=$1 AND action='software.task.reported'`, task.Context.TaskID).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("receipt retry duplicated audit", audits, err)
	}
	reply, err = f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID})
	if err != nil || reply.Task != nil {
		t.Fatal("completed command redelivered", err)
	}
	changed := *result
	changed.SignedAt++
	if _, err = f.submit(t, &changed); err == nil {
		t.Fatal("changed terminal receipt accepted")
	}
	for _, q := range []string{`UPDATE uem_agent_software_tasks SET status='pending' WHERE status='reported'`, `UPDATE uem_agent_software_tasks SET envelope='\\x'`, `DELETE FROM uem_agent_software_tasks`, `TRUNCATE uem_agent_software_tasks`} {
		if _, err = f.store.db.Exec(q); err == nil {
			t.Fatal("command evidence overwritten", q)
		}
	}
	_ = f.queue(t)
}

func TestSoftwareTaskRegistryPreservesInterruptedAndRestartReservations(t *testing.T) {
	for _, state := range []string{"uncertain", "restart_required"} {
		t.Run(state, func(t *testing.T) {
			f := newSoftwareFixture(t)
			task := f.queue(t)
			if _, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.submit(t, f.result(t, task, state)); err != nil {
				t.Fatal(err)
			}
			tx, err := f.store.db.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err = f.store.QueueSoftwareTaskInTransaction(t.Context(), tx, f.identity.Scope, f.identity.ID, uuid.NewString(), uuid.NewString(), uuid.NewString(), softwarePlan(), time.Now().Add(5*time.Minute), "operator"); err == nil {
				t.Fatal("uncertain/restart operation lost its reservation")
			}
		})
	}
}

func TestSoftwareTaskRegistryAuditFailuresDoNotLoseWork(t *testing.T) {
	f := newSoftwareFixture(t)
	task := f.queue(t)
	_, err := f.store.db.Exec(`CREATE FUNCTION reject_software_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action LIKE 'software.task.%' THEN RAISE EXCEPTION 'owned audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_software_audit BEFORE INSERT ON uem_agent_audit FOR EACH ROW EXECUTE FUNCTION reject_software_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	if reply, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID}); err == nil || reply != nil {
		t.Fatal("task escaped before delivery audit")
	}
	var delivered sql.NullTime
	if err = f.store.db.QueryRow(`SELECT delivered_at FROM uem_agent_software_tasks WHERE id=$1`, task.Context.TaskID).Scan(&delivered); err != nil || delivered.Valid {
		t.Fatal("failed audit consumed delivery", err)
	}
	if _, err = f.store.db.Exec(`DROP TRIGGER reject_software_audit ON uem_agent_audit`); err != nil {
		t.Fatal(err)
	}
	if _, err = f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.db.Exec(`CREATE TRIGGER reject_software_audit BEFORE INSERT ON uem_agent_audit FOR EACH ROW EXECUTE FUNCTION reject_software_audit()`); err != nil {
		t.Fatal(err)
	}
	if reply, err := f.submit(t, f.result(t, task, "observed")); err == nil || reply != nil {
		t.Fatal("receipt survived failed audit")
	}
	var raw []byte
	if err = f.store.db.QueryRow(`SELECT result FROM uem_agent_software_tasks WHERE id=$1`, task.Context.TaskID).Scan(&raw); err != nil || raw != nil {
		t.Fatal("failed result consumed operation", err)
	}
}

func TestSoftwareTaskRegistryRejectsForeignScopeAndUnregisteredProofs(t *testing.T) {
	f := newSoftwareFixture(t)
	_ = f.queue(t)
	original := *f.identity
	for _, change := range []func(*Identity){func(i *Identity) { i.SiteID = 3 }, func(i *Identity) { i.TenantID = 2 }, func(i *Identity) { i.Platform = "macos" }} {
		change(f.identity)
		if reply, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID}); err == nil || reply != nil {
			t.Fatal("foreign platform/scope read task")
		}
		*f.identity = original
	}
	if _, err := f.call(t.Context(), enrollment.SoftwareRequest{AgentID: uuid.NewString(), Action: "poll", RecipientID: f.recipient.ID}); err == nil {
		t.Fatal("foreign subject binding accepted")
	}
	if _, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: uuid.NewString()}); err == nil {
		t.Fatal("unknown recipient polled")
	}
	if err := f.store.RevokeIdentity(t.Context(), f.identity.Scope, f.identity.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID}); err == nil {
		t.Fatal("revoked identity polled")
	}
	var status string
	if err := f.store.db.QueryRow(`SELECT status FROM uem_agent_software_tasks WHERE device_id=$1`, f.identity.ID).Scan(&status); err != nil || status != "cancelled" {
		t.Fatal("undelivered task survived revocation", status, err)
	}
}

func TestSoftwareSubmissionRequiresTheCurrentCertificateGeneration(t *testing.T) {
	f := newSoftwareFixture(t)
	task := f.queue(t)
	if _, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID}); err != nil {
		t.Fatal(err)
	}
	result := f.result(t, task, "observed")
	retiredProof, err := enrollment.SignSoftwareSubmission(*result, f.recipient.Identity, f.cert, f.signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Preserve a signed offline result across two real CA-issued generations.
	// Each handoff reserves its new key and retires the prior source generation.
	for range 2 {
		keys, err := enrollment.GenerateKeys()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(keys.Broker.Wipe)
		var root, sealed []byte
		if err = f.store.db.QueryRow(`SELECT certificate,encrypted_key FROM uem_agent_authorities WHERE tenant_id=1`).Scan(&root, &sealed); err != nil {
			t.Fatal(err)
		}
		raw, err := f.store.open(sealed, "1/authority/key")
		if err != nil {
			t.Fatal(err)
		}
		ca, issuer, err := parseAuthority(root, raw)
		clear(raw)
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
		_, err = f.store.db.Exec(`UPDATE uem_agent_identities SET certificate=$2,certificate_hash=$3,certificate_key_hash=$4,certificate_expires_at=$5 WHERE id=$1`, f.identity.ID, issued, digest(cert.Raw), digest(public), expires)
		if err != nil {
			t.Fatal(err)
		}
		f.cert, f.signer = cert, keys.Certificate
	}
	if _, err = f.call(t.Context(), enrollment.SoftwareRequest{Action: "result", Result: result, Submission: retiredProof}); err == nil {
		t.Fatal("retired certificate submitted via stale broker subject")
	}
	reply, err := f.submit(t, result)
	if err != nil || reply.Receipt == nil {
		t.Fatal("current proof could not recover historical result", err)
	}
	encoded, _ := json.Marshal(result)
	var stored []byte
	if err = f.store.db.QueryRow(`SELECT result FROM uem_agent_software_tasks WHERE id=$1`, task.Context.TaskID).Scan(&stored); err != nil || !bytes.Equal(stored, encoded) {
		t.Fatal("historical signed result changed", err)
	}
}
