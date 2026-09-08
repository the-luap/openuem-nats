package registry

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

func testRecoveryAgent(t *testing.T, s *Store) (*AccessStore, *Identity, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	invite, err := s.Invite(t.Context(), InvitationOptions{Scope: Scope{TenantID: 1, SiteID: 1}, Platform: "macos", Architecture: "arm64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	token := invite.URL[strings.LastIndex(invite.URL, "/")+1:]
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	request, err := keys.Request(token, "macos", "arm64", "Recovery Mac")
	if err != nil {
		t.Fatal(err)
	}
	response, err := s.Claim(t.Context(), *request)
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
	block, _ := pem.Decode([]byte(response.Certificate))
	if block == nil {
		t.Fatal("missing fixture certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return access, identity, certificate, keys.Certificate
}

func testRegisterRecovery(t *testing.T, access *AccessStore, identity *Identity, cert *x509.Certificate, signer *rsa.PrivateKey, key *enrollment.RecoveryRecipientKey) (*enrollment.RecoveryRecipient, *enrollment.RecoveryRegistration, []byte) {
	t.Helper()
	reply, err := access.HandleRecovery(t.Context(), *identity, enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "challenge", PublicKey: key.PublicKey()})
	if err != nil || reply.Registration == nil {
		t.Fatal("challenge failed", err)
	}
	challenge := reply.Registration
	signature, err := enrollment.SignRecoveryRegistration(*challenge, cert, signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	reply, err = access.HandleRecovery(t.Context(), *identity, enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "register", Registration: challenge, Signature: signature})
	if err != nil || reply.Recipient == nil {
		t.Fatal("registration failed", err)
	}
	return reply.Recipient, challenge, signature
}

func testQueueRecovery(t *testing.T, s *Store, access *AccessStore, identity *Identity, recipient *enrollment.RecoveryRecipient) *enrollment.RecoveryTask {
	t.Helper()
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	current, cert, err := access.RecoveryRecipient(t.Context(), tx, identity.Scope, identity.ID)
	if err != nil || current.ID != recipient.ID {
		t.Fatal("recipient lookup failed", err)
	}
	c := enrollment.RecoveryContext{Version: 1, Identity: recipient.Identity, TaskID: uuid.NewString(), NativeID: uuid.NewString(), KeyID: uuid.NewString(), RecipientID: recipient.ID, ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}
	if c.ExpiresAt > cert.NotAfter.Unix() {
		t.Fatal("invalid fixture expiry")
	}
	nonce := bytes.Repeat([]byte{8}, 32)
	task, err := enrollment.EncryptRecoveryTask(*recipient, c, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = access.QueueRecoveryTask(t.Context(), tx, *task, digest(nonce)); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return task
}

func TestRecoveryRegistrationTasksAndSignedReceipts(t *testing.T) {
	s := testStore(t)
	access, identity, cert, signer := testRecoveryAgent(t, s)
	if !access.RecoveryReady(t.Context()) {
		t.Fatal("recovery schema not ready")
	}
	key, err := enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	recipient, challenge, signature := testRegisterRecovery(t, access, identity, cert, signer, key)
	request := enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "register", Registration: challenge, Signature: signature}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := access.HandleRecovery(t.Context(), *identity, request)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("idempotent registration failed", err)
		}
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE action='recovery.recipient.registered'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate registration created audit events", count, err)
	}
	reply, err := access.HandleRecovery(t.Context(), *identity, enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "challenge", PublicKey: key.PublicKey()})
	if err != nil || reply.Recipient == nil || reply.Recipient.ID != recipient.ID {
		t.Fatal("known recipient required another registration", err)
	}
	task := testQueueRecovery(t, s, access, identity, recipient)
	secret, err := key.Open(*task, recipient.Identity, recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	result, err := secret.Result("invalid", cert, signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resultRequest := enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "result", Result: result}
	if _, err = access.HandleRecovery(t.Context(), *identity, resultRequest); !errors.Is(err, ErrDenied) {
		t.Fatal("undelivered task accepted result", err)
	}
	poll := enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "poll", RecipientID: recipient.ID}
	reply, err = access.HandleRecovery(t.Context(), *identity, poll)
	if err != nil || reply.Task == nil || reply.Task.Context != task.Context {
		t.Fatal("wrong private task delivered", err)
	}
	result.Outcome = "valid"
	if _, err = access.HandleRecovery(t.Context(), *identity, resultRequest); !errors.Is(err, ErrDenied) {
		t.Fatal("forged result accepted", err)
	}
	result.Outcome = "invalid"
	if _, err = s.db.Exec(`ALTER TABLE uem_agent_audit ADD CONSTRAINT recovery_audit_failure CHECK(action!='recovery.validation.reported')`); err != nil {
		t.Fatal(err)
	}
	if _, err = access.HandleRecovery(t.Context(), *identity, resultRequest); err == nil {
		t.Fatal("result committed without its audit record")
	}
	var unchanged bool
	if err = s.db.QueryRow(`SELECT status='pending' AND octet_length(envelope)>0 AND result IS NULL FROM uem_agent_recovery_tasks WHERE id=$1`, task.Context.TaskID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("audit failure did not roll back the private task", err)
	}
	if _, err = s.db.Exec(`ALTER TABLE uem_agent_audit DROP CONSTRAINT recovery_audit_failure`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err = access.HandleRecovery(t.Context(), *identity, resultRequest); err != nil {
			t.Fatal("signed result or its idempotent retry rejected", err)
		}
	}
	var state string
	var envelope, stored []byte
	if err = s.db.QueryRow(`SELECT status,envelope,result FROM uem_agent_recovery_tasks WHERE id=$1`, task.Context.TaskID).Scan(&state, &envelope, &stored); err != nil || state != "completed" || len(envelope) != 0 {
		t.Fatal("terminal private task retained envelope", err)
	}
	var receipt enrollment.RecoveryResult
	if json.Unmarshal(stored, &receipt) != nil || receipt.Outcome != "invalid" || enrollment.VerifyRecoveryResult(receipt, cert, time.Now()) != nil {
		t.Fatal("stored receipt lost authenticated outcome")
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE action='recovery.validation.reported'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate result inflated audit", count, err)
	}
	reply, err = access.HandleRecovery(t.Context(), *identity, poll)
	if err != nil || reply.Task != nil {
		t.Fatal("completed task was redelivered", err)
	}
	var document []byte
	if err = s.db.QueryRow(`SELECT json_agg(t)::text FROM uem_agent_recovery_tasks t`).Scan(&document); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(document, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")) {
		t.Fatal("routing database received recovery plaintext")
	}
}

func TestRecoveryRecipientReplacementRejectsOldProofAndCancelsOldTasks(t *testing.T) {
	s := testStore(t)
	access, identity, cert, signer := testRecoveryAgent(t, s)
	first, err := enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	r, old, signature := testRegisterRecovery(t, access, identity, cert, signer, first)
	task := testQueueRecovery(t, s, access, identity, r)
	second, err := enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	newRecipient, _, _ := testRegisterRecovery(t, access, identity, cert, signer, second)
	if newRecipient.ID == r.ID {
		t.Fatal("recipient epoch reused")
	}
	if _, err = access.HandleRecovery(t.Context(), *identity, enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "register", Registration: old, Signature: signature}); !errors.Is(err, ErrDenied) {
		t.Fatal("old signed registration rolled back recipient", err)
	}
	var state string
	var size int
	if err = s.db.QueryRow(`SELECT status,octet_length(envelope) FROM uem_agent_recovery_tasks WHERE id=$1`, task.Context.TaskID).Scan(&state, &size); err != nil || state != "cancelled" || size != 0 {
		t.Fatal("old recipient retained queued private task", state, size, err)
	}
	for _, mutate := range []func(*Identity){func(i *Identity) { i.SiteID = 2 }, func(i *Identity) { i.TenantID = 2 }, func(i *Identity) { i.Platform = "windows" }} {
		wrong := *identity
		mutate(&wrong)
		if _, err = access.HandleRecovery(t.Context(), wrong, enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "poll", RecipientID: newRecipient.ID}); !errors.Is(err, ErrDenied) {
			t.Fatal("foreign scope accepted recovery RPC", err)
		}
	}
	task = testQueueRecovery(t, s, access, identity, newRecipient)
	if err = s.RevokeIdentity(t.Context(), identity.Scope, identity.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = access.HandleRecovery(t.Context(), *identity, enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "poll", RecipientID: newRecipient.ID}); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked identity polled recovery tasks", err)
	}
	if err = s.db.QueryRow(`SELECT status,octet_length(envelope) FROM uem_agent_recovery_tasks WHERE id=$1`, task.Context.TaskID).Scan(&state, &size); err != nil || state != "cancelled" || size != 0 {
		t.Fatal("revocation retained private envelope", state, size, err)
	}
}

func TestRecoveryExpiryAndChangedSiteOwnershipErasePendingCiphertext(t *testing.T) {
	s := testStore(t)
	access, identity, cert, signer := testRecoveryAgent(t, s)
	key, err := enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	r, _, _ := testRegisterRecovery(t, access, identity, cert, signer, key)
	task := testQueueRecovery(t, s, access, identity, r)
	if _, err = s.db.Exec(`UPDATE uem_agent_recovery_tasks SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, task.Context.TaskID); err != nil {
		t.Fatal(err)
	}
	if err = access.ExpireRecoveryTasks(t.Context()); err != nil {
		t.Fatal(err)
	}
	var state string
	var size int
	if err = s.db.QueryRow(`SELECT status,octet_length(envelope) FROM uem_agent_recovery_tasks WHERE id=$1`, task.Context.TaskID).Scan(&state, &size); err != nil || state != "expired" || size != 0 {
		t.Fatal("expiry did not erase private task", err)
	}
	task = testQueueRecovery(t, s, access, identity, r)
	if _, err = s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err = access.ExpireRecoveryTasks(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow(`SELECT status,octet_length(envelope) FROM uem_agent_recovery_tasks WHERE id=$1`, task.Context.TaskID).Scan(&state, &size); err != nil || state != "cancelled" || size != 0 {
		t.Fatal("changed site ownership retained private task", err)
	}
}
