package registry

import (
	"bytes"
	"crypto/x509"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
)

func (f *identityRenewalFixture) prepareConfirmation(t *testing.T) (*PreparedIdentityRenewal, enrollment.RenewalConfirmationTarget, *enrollment.RenewalConfirmation) {
	t.Helper()
	p, err := f.s.PrepareIdentityRenewal(t.Context(), *f.request)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := enrollment.ValidateResponse(p.Response, f.source.Origin, &f.candidate.Certificate.PublicKey, f.now)
	if err != nil {
		t.Fatal(err)
	}
	candidate := f.source
	candidate.Certificate = cert.Raw
	candidate.BrokerKey, _ = f.candidate.Broker.PublicKey()
	target := enrollment.RenewalConfirmationTarget{RequestID: p.ID, SourceCertificateHash: p.SourceCertificateHash, Candidate: candidate}
	request, err := enrollment.NewRenewalConfirmation(target, f.candidate, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return p, target, request
}

func TestIdentityRenewalConfirmationPreservesDeviceAndRecoversCommittedHandoff(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(map[bool]string{true: "same keys", false: "fresh keys"}[retained], func(t *testing.T) {
			f := newIdentityRenewalFixture(t)
			if retained {
				f.candidate = f.current
				var err error
				f.request, err = enrollment.NewRenewalRequest(f.source, f.current, f.candidate, f.request.RequestID, f.now)
				if err != nil {
					t.Fatal(err)
				}
			}
			_, target, request := f.prepareConfirmation(t)
			access, _ := NewAccessStore(f.s.db)
			server, _ := nkeys.CreateServer()
			serverID, _ := server.PublicKey()
			server.Wipe()
			session := func(id uint64) enrollment.BrokerSession {
				return enrollment.BrokerSession{ServerID: serverID, ClientID: id, ExpiresAt: time.Now().Add(enrollment.BrokerLease)}
			}
			if _, err := access.AuthorizeDevice(t.Context(), f.source.BrokerKey, session(1)); err != nil {
				t.Fatal(err)
			}
			if !retained {
				if _, err := access.AuthorizeDevice(t.Context(), target.Candidate.BrokerKey, session(2)); !errors.Is(err, ErrDenied) {
					t.Fatal("pending broker key was authorized", err)
				}
			}
			var before, consumer []byte
			const stableIdentity = `SELECT (to_jsonb(i)-ARRAY['key_binding','certificate_key_hash','broker_key','certificate','authority_certificate','certificate_hash','certificate_expires_at'])::text FROM uem_agent_identities i WHERE id=$1`
			if err := f.s.db.QueryRow(stableIdentity, f.source.DeviceID).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if err := f.s.db.QueryRow(`SELECT row_to_json(q)::text FROM uem_agent_command_consumers q WHERE device_id=$1`, f.source.DeviceID).Scan(&consumer); err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			results := make(chan *ConfirmedIdentityRenewal, 8)
			failures := make(chan error, 8)
			for range 8 {
				wg.Go(func() {
					r, err := f.s.ConfirmIdentityRenewal(t.Context(), *request)
					if err != nil {
						failures <- err
					} else {
						results <- r
					}
				})
			}
			wg.Wait()
			close(results)
			close(failures)
			for err := range failures {
				t.Fatal(err)
			}
			var first *ConfirmedIdentityRenewal
			for r := range results {
				if first == nil {
					first = r
				} else if !reflect.DeepEqual(first, r) {
					t.Fatal("confirmation retry changed committed evidence")
				}
			}
			if first == nil || first.CertificateHash != request.CertificateHash || first.DeviceID != f.source.DeviceID {
				t.Fatal("confirmation changed identity")
			}
			var after, afterConsumer []byte
			if err := f.s.db.QueryRow(stableIdentity, f.source.DeviceID).Scan(&after); err != nil || !bytes.Equal(before, after) {
				t.Fatal("activation changed stable device state", err)
			}
			if err := f.s.db.QueryRow(`SELECT row_to_json(q)::text FROM uem_agent_command_consumers q WHERE device_id=$1`, f.source.DeviceID).Scan(&afterConsumer); err != nil || !bytes.Equal(consumer, afterConsumer) {
				t.Fatal("activation recreated device command consumer", err)
			}
			oldCert, _ := x509.ParseCertificate(f.source.Certificate)
			newCert, _ := x509.ParseCertificate(target.Candidate.Certificate)
			if _, err := access.AuthenticateCertificate(t.Context(), f.source.DeviceID, oldCert); !errors.Is(err, ErrDenied) {
				t.Fatal("retired certificate remained current", err)
			}
			if _, err := access.AuthenticateCertificate(t.Context(), f.source.DeviceID, newCert); err != nil {
				t.Fatal("candidate certificate was not activated", err)
			}
			if !retained {
				if _, err := access.AuthorizeDevice(t.Context(), f.source.BrokerKey, session(3)); !errors.Is(err, ErrDenied) {
					t.Fatal("retired broker key reconnected", err)
				}
			}
			if _, err := access.AuthorizeDevice(t.Context(), target.Candidate.BrokerKey, session(4)); err != nil {
				t.Fatal("new broker key cannot reconnect", err)
			}
			disconnects, err := access.PendingDisconnects(t.Context(), 20)
			if err != nil || len(disconnects) != 1 || disconnects[0].ClientID != 1 {
				t.Fatal("activation did not isolate old broker sessions", disconnects, err)
			}
			// A restart and fresh proof after preparation/source expiry still recover
			// the committed handoff, without disconnecting the new session again.
			restarted, _ := NewStore(f.s.db, testMaster)
			later := f.now.Add(21 * 24 * time.Hour)
			restarted.renewalClock = func() time.Time { return later }
			fresh, err := enrollment.NewRenewalConfirmation(target, f.candidate, later)
			if err != nil {
				t.Fatal(err)
			}
			again, err := restarted.ConfirmIdentityRenewal(t.Context(), *fresh)
			if err != nil || !reflect.DeepEqual(first, again) {
				t.Fatal("restart lost committed handoff", err)
			}
			var records, audits, newDisconnects int
			if err := f.s.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_identity_renewal_confirmations),(SELECT count(*) FROM uem_agent_audit WHERE action='agent.identity.renew.confirm'),(SELECT count(*) FROM uem_agent_broker_sessions WHERE client_id=4 AND disconnect_at IS NOT NULL)`).Scan(&records, &audits, &newDisconnects); err != nil || records != 1 || audits != 1 || newDisconnects != 0 {
				t.Fatal("retry repeated handoff side effects", records, audits, newDisconnects, err)
			}
			if _, err := f.s.PrepareIdentityRenewal(t.Context(), *f.request); !errors.Is(err, ErrDenied) {
				t.Fatal("source preparation was replayed after activation", err)
			}
			for _, statement := range []string{`DELETE FROM uem_agent_identity_renewal_confirmations`, `UPDATE uem_agent_identity_renewal_confirmations SET confirmed_at=confirmed_at`, `TRUNCATE uem_agent_identity_renewal_confirmations`} {
				if _, err := f.s.db.Exec(statement); err == nil {
					t.Fatal("confirmation evidence was mutable")
				}
			}
		})
	}
}

func TestIdentityRenewalOldConfirmationCannotRollBackLaterGeneration(t *testing.T) {
	f := newIdentityRenewalFixture(t)
	_, target, request := f.prepareConfirmation(t)
	if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *request); err != nil {
		t.Fatal(err)
	}
	later := f.now.Add(61 * 24 * time.Hour)
	f.s.renewalClock = func() time.Time { return later }
	q, err := enrollment.NewRenewalRequest(target.Candidate, f.candidate, f.candidate, uuid.NewString(), later)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.s.PrepareIdentityRenewal(t.Context(), *q)
	if err != nil {
		t.Fatal("next due generation could not prepare", err)
	}
	cert, err := enrollment.ValidateResponse(p.Response, f.source.Origin, &f.candidate.Certificate.PublicKey, later)
	if err != nil {
		t.Fatal(err)
	}
	next := target
	next.RequestID, next.SourceCertificateHash, next.Candidate.Certificate = p.ID, p.SourceCertificateHash, cert.Raw
	confirm, err := enrollment.NewRenewalConfirmation(next, f.candidate, later)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); err != nil {
		t.Fatal(err)
	}
	old, err := enrollment.NewRenewalConfirmation(target, f.candidate, later)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *old); !errors.Is(err, ErrDenied) {
		t.Fatal("old confirmation rolled back current generation", err)
	}
	var hash string
	if err := f.s.db.QueryRow(`SELECT certificate_hash FROM uem_agent_identities WHERE id=$1`, f.source.DeviceID).Scan(&hash); err != nil || hash != confirm.CertificateHash {
		t.Fatal("old confirmation changed current certificate", err)
	}
	_, token := invite(t, f.s, Scope{TenantID: 2, SiteID: 2}, 1)
	if _, err := f.s.Claim(t.Context(), *proof(t, token, f.current)); !errors.Is(err, ErrDenied) {
		t.Fatal("retired keys were reassigned to another device", err)
	}
}

func TestIdentityRenewalConfirmationAuditFailureRollsBackAllHandoffState(t *testing.T) {
	f := newIdentityRenewalFixture(t)
	_, _, request := f.prepareConfirmation(t)
	if _, err := f.s.db.Exec(`CREATE FUNCTION reject_confirmation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='agent.identity.renew.confirm' THEN RAISE EXCEPTION 'synthetic confirmation audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_confirmation_audit BEFORE INSERT ON uem_agent_audit FOR EACH ROW EXECUTE FUNCTION reject_confirmation_audit()`); err != nil {
		t.Fatal(err)
	}
	if r, err := f.s.ConfirmIdentityRenewal(t.Context(), *request); err == nil || r != nil {
		t.Fatal("uncommitted confirmation was released")
	}
	var hash string
	var count int
	if err := f.s.db.QueryRow(`SELECT certificate_hash,(SELECT count(*) FROM uem_agent_identity_renewal_confirmations) FROM uem_agent_identities WHERE id=$1`, f.source.DeviceID).Scan(&hash, &count); err != nil || hash != digest(f.source.Certificate) || count != 0 {
		t.Fatal("failed audit left activation state", err)
	}
	if _, err := f.s.db.Exec(`DROP TRIGGER reject_confirmation_audit ON uem_agent_audit`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *request); err != nil {
		t.Fatal("rolled-back handoff cannot retry", err)
	}
}

func TestIdentityRenewalConfirmationCannotRacePastRevocation(t *testing.T) {
	f := newIdentityRenewalFixture(t)
	_, _, request := f.prepareConfirmation(t)
	var wg sync.WaitGroup
	errorsOut := make(chan error, 2)
	wg.Go(func() {
		_, err := f.s.ConfirmIdentityRenewal(t.Context(), *request)
		if err != nil && !errors.Is(err, ErrDenied) {
			errorsOut <- err
		}
	})
	wg.Go(func() {
		if err := f.s.RevokeIdentity(t.Context(), Scope{TenantID: 1, SiteID: 1}, f.source.DeviceID, "test-admin"); err != nil {
			errorsOut <- err
		}
	})
	wg.Wait()
	close(errorsOut)
	for err := range errorsOut {
		t.Fatal(err)
	}
	if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *request); !errors.Is(err, ErrDenied) {
		t.Fatal("confirmation revived revoked identity", err)
	}
	access, _ := NewAccessStore(f.s.db)
	if _, err := access.ActiveIdentity(t.Context(), f.source.DeviceID); !errors.Is(err, ErrDenied) {
		t.Fatal("revocation was lost", err)
	}
}

func TestIdentityRenewalConfirmationRejectsExpiredPreparationAndForeignScope(t *testing.T) {
	for _, changed := range []string{"expired", "site", "origin", "proof"} {
		t.Run(changed, func(t *testing.T) {
			f := newIdentityRenewalFixture(t)
			_, target, request := f.prepareConfirmation(t)
			switch changed {
			case "expired":
				later := f.now.Add(IdentityRenewalPreparationLifetime + time.Minute)
				f.s.renewalClock = func() time.Time { return later }
				var err error
				request, err = enrollment.NewRenewalConfirmation(target, f.candidate, later)
				if err != nil {
					t.Fatal(err)
				}
			case "site":
				if _, err := f.s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`); err != nil {
					t.Fatal(err)
				}
			case "origin":
				if _, err := f.s.db.Exec(`UPDATE uem_agent_authorities SET public_origin='https://other.example.test' WHERE tenant_id=1`); err != nil {
					t.Fatal(err)
				}
			case "proof":
				request.BrokerProof = f.request.CandidateBrokerProof
			}
			if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *request); !errors.Is(err, ErrDenied) {
				t.Fatal("unauthorized handoff accepted", err)
			}
			var count int
			if err := f.s.db.QueryRow(`SELECT count(*) FROM uem_agent_identity_renewal_confirmations`).Scan(&count); err != nil || count != 0 {
				t.Fatal("denied handoff persisted confirmation", err)
			}
		})
	}
}

func TestIdentityRenewalConfirmationPreservesRecoveryUncertaintyAndReceiptHistory(t *testing.T) {
	for _, state := range []string{"undelivered", "delivered", "uncertain", "cancelled delivered", "read-only"} {
		t.Run(state, func(t *testing.T) {
			f := newIdentityRenewalFixture(t)
			if _, err := f.s.db.Exec(`UPDATE uem_agent_identities SET platform='macos' WHERE id=$1`, f.source.DeviceID); err != nil {
				t.Fatal(err)
			}
			f.source.Platform = "macos"
			var err error
			f.request, err = enrollment.NewRenewalRequest(f.source, f.current, f.candidate, f.request.RequestID, f.now)
			if err != nil {
				t.Fatal(err)
			}
			_, _, confirm := f.prepareConfirmation(t)
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
			var task *enrollment.RotationTask
			var receipt []byte
			if state == "read-only" {
				testQueueRecovery(t, f.s, access, identity, recipient)
				if _, err := access.HandleRecovery(t.Context(), *identity, enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "poll", RecipientID: recipient.ID}); err != nil {
					t.Fatal(err)
				}
			} else {
				task = rf.queue(t)
				if state != "undelivered" {
					if _, err := access.HandleRotation(t.Context(), *identity, rf.pollRequest()); err != nil {
						t.Fatal(err)
					}
				}
				if state == "uncertain" {
					if _, err := access.HandleRotation(t.Context(), *identity, rf.result(t, task.Context, "uncertain")); err != nil {
						t.Fatal(err)
					}
					if err := f.s.db.QueryRow(`SELECT result FROM uem_agent_rotation_tasks WHERE id=$1`, task.Context.Binding.TaskID).Scan(&receipt); err != nil {
						t.Fatal(err)
					}
				}
				if state == "cancelled delivered" {
					// An older trusted component may cancel an epoch without proving
					// execution stopped. Renewal must retain that unresolved evidence.
					if _, err := f.s.db.Exec(`UPDATE uem_agent_rotation_tasks SET status='cancelled' WHERE id=$1`, task.Context.Binding.TaskID); err != nil {
						t.Fatal(err)
					}
				}
			}
			if state != "undelivered" {
				if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); !errors.Is(err, ErrRenewalRecoveryPending) {
					t.Fatal("handoff erased unfinished recovery work", err)
				}
				var hash string
				if err := f.s.db.QueryRow(`SELECT certificate_hash FROM uem_agent_identities WHERE id=$1`, identity.ID).Scan(&hash); err != nil || hash != digest(f.source.Certificate) {
					t.Fatal("blocked handoff changed certificate", err)
				}
				if state == "uncertain" {
					var after []byte
					if err := f.s.db.QueryRow(`SELECT result FROM uem_agent_rotation_tasks WHERE id=$1 AND status='uncertain'`, task.Context.Binding.TaskID).Scan(&after); err != nil || !bytes.Equal(receipt, after) {
						t.Fatal("handoff changed signed uncertainty", err)
					}
				}
				if state != "delivered" {
					return
				}
				// Worker receipt delivery still cannot release handoff before the
				// trusted key processor has durably acknowledged reconciliation.
				if _, err := access.HandleRotation(t.Context(), *identity, rf.result(t, task.Context, "rotated")); err != nil {
					t.Fatal(err)
				}
				if err := f.s.db.QueryRow(`SELECT result FROM uem_agent_rotation_tasks WHERE id=$1`, task.Context.Binding.TaskID).Scan(&receipt); err != nil {
					t.Fatal(err)
				}
				if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); !errors.Is(err, ErrRenewalRecoveryPending) {
					t.Fatal("worker receipt alone released handoff", err)
				}
				ack := func(commit bool, expectedHash string) error {
					tx, err := f.s.db.BeginTx(t.Context(), nil)
					if err != nil {
						return err
					}
					defer tx.Rollback()
					if err := f.s.AcknowledgeRotationReconciliationInTransaction(t.Context(), tx, identity.Scope, identity.ID, task.Context.Binding.TaskID, expectedHash, "test-key-processor"); err != nil {
						return err
					}
					if commit {
						return tx.Commit()
					}
					return nil
				}
				if err := ack(true, digest([]byte("different signed receipt"))); !errors.Is(err, ErrDenied) {
					t.Fatal("acknowledgement omitted exact receipt binding", err)
				}
				if err := ack(false, digest(receipt)); err != nil {
					t.Fatal(err)
				}
				if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); !errors.Is(err, ErrRenewalRecoveryPending) {
					t.Fatal("rolled-back key processing released handoff", err)
				}
				for range 2 {
					if err := ack(true, digest(receipt)); err != nil {
						t.Fatal(err)
					}
				}
				var acknowledgements, audits int
				if err := f.s.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_rotation_reconciliations),(SELECT count(*) FROM uem_agent_audit WHERE action='recovery.rotation.reconciled')`).Scan(&acknowledgements, &audits); err != nil || acknowledgements != 1 || audits != 1 {
					t.Fatal("reconciliation retry duplicated evidence", err)
				}
				for _, statement := range []string{`DELETE FROM uem_agent_rotation_reconciliations`, `UPDATE uem_agent_rotation_reconciliations SET device_id=device_id`, `TRUNCATE uem_agent_rotation_reconciliations`} {
					if _, err := f.s.db.Exec(statement); err == nil {
						t.Fatal("reconciliation evidence was mutable")
					}
				}
				var sealed []byte
				if err := f.s.db.QueryRow(`SELECT encrypted_record FROM uem_agent_rotation_reconciliations`).Scan(&sealed); err != nil {
					t.Fatal(err)
				}
				if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_rotation_reconciliations DISABLE TRIGGER uem_agent_rotation_reconciliation_immutable; UPDATE uem_agent_rotation_reconciliations SET encrypted_record=set_byte(encrypted_record,20,get_byte(encrypted_record,20)#1); ALTER TABLE uem_agent_rotation_reconciliations ENABLE TRIGGER uem_agent_rotation_reconciliation_immutable`); err != nil {
					t.Fatal(err)
				}
				if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); !errors.Is(err, ErrUnavailable) {
					t.Fatal("forged key processing evidence released handoff", err)
				}
				if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_rotation_reconciliations DISABLE TRIGGER uem_agent_rotation_reconciliation_immutable`); err != nil {
					t.Fatal(err)
				}
				if _, err := f.s.db.Exec(`UPDATE uem_agent_rotation_reconciliations SET encrypted_record=$1`, sealed); err != nil {
					t.Fatal(err)
				}
				if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_rotation_reconciliations ENABLE TRIGGER uem_agent_rotation_reconciliation_immutable`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); err != nil {
				t.Fatal("settled recovery work blocked handoff", err)
			}
			var recipients int
			if err := f.s.db.QueryRow(`SELECT count(*) FROM uem_agent_recovery_recipients WHERE device_id=$1`, identity.ID).Scan(&recipients); err != nil || recipients != 0 {
				t.Fatal("old recovery recipient remained active", err)
			}
			if state == "undelivered" {
				rf.state(t, task.Context.Binding.TaskID, "cancelled", false)
			} else {
				var after []byte
				if err := f.s.db.QueryRow(`SELECT result FROM uem_agent_rotation_tasks WHERE id=$1 AND status='completed'`, task.Context.Binding.TaskID).Scan(&after); err != nil || !bytes.Equal(receipt, after) {
					t.Fatal("handoff lost completed receipt history", err)
				}
			}
		})
	}
}

func TestIdentityRenewalConfirmationRechecksProofFreshnessAfterAudit(t *testing.T) {
	f := newIdentityRenewalFixture(t)
	_, _, request := f.prepareConfirmation(t)
	calls := 0
	f.s.renewalClock = func() time.Time {
		calls++
		if calls >= 3 {
			return f.now.Add(enrollment.RenewalProofLifetime + time.Second)
		}
		return f.now
	}
	if result, err := f.s.ConfirmIdentityRenewal(t.Context(), *request); !errors.Is(err, ErrDenied) || result != nil {
		t.Fatal("confirmation committed after proof expired", err)
	}
	var count int
	var hash string
	if err := f.s.db.QueryRow(`SELECT certificate_hash,(SELECT count(*) FROM uem_agent_identity_renewal_confirmations)+(SELECT count(*) FROM uem_agent_audit WHERE action='agent.identity.renew.confirm') FROM uem_agent_identities WHERE id=$1`, f.source.DeviceID).Scan(&hash, &count); err != nil || hash != digest(f.source.Certificate) || count != 0 {
		t.Fatal("proof expiry left handoff changes", err)
	}
}
