package registry

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
)

func renewalResolutionProof(t *testing.T, f *identityRenewalFixture, target enrollment.RenewalConfirmationTarget, at time.Time) *enrollment.RenewalResolution {
	t.Helper()
	request, err := enrollment.NewRenewalResolution(target, f.candidate, at)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func renewalRetainedState(t *testing.T, s *Store) []string {
	t.Helper()
	var state []string
	for _, table := range []string{"uem_agent_identities", "uem_agent_command_consumers", "uem_agent_broker_sessions", "uem_agent_recovery_recipients", "uem_agent_recovery_tasks", "uem_agent_rotation_tasks", "uem_agent_key_reservations", "uem_agent_invitations"} {
		var value string
		if err := s.db.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]')::text FROM ` + table + ` q`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		state = append(state, value)
	}
	return state
}

func TestIdentityRenewalResolutionCancelsPermanentlyWithoutChangingCurrentState(t *testing.T) {
	for _, afterExpiry := range []bool{false, true} {
		t.Run(map[bool]string{false: "before preparation expiry", true: "after preparation expiry"}[afterExpiry], func(t *testing.T) {
			f := newIdentityRenewalFixture(t)
			_, target, confirm := f.prepareConfirmation(t)
			access, _ := NewAccessStore(f.s.db)
			server, _ := nkeys.CreateServer()
			serverID, _ := server.PublicKey()
			server.Wipe()
			if _, err := access.AuthorizeDevice(t.Context(), f.source.BrokerKey, enrollment.BrokerSession{ServerID: serverID, ClientID: 1, ExpiresAt: time.Now().Add(enrollment.BrokerLease)}); err != nil {
				t.Fatal(err)
			}
			before := renewalRetainedState(t, f.s)
			at := f.now
			if afterExpiry {
				at = at.Add(IdentityRenewalPreparationLifetime + time.Minute)
			}
			f.s.renewalClock = func() time.Time { return at }
			request := renewalResolutionProof(t, f, target, at)
			result, err := f.s.ResolveIdentityRenewal(t.Context(), *request)
			if err != nil || result.Outcome != "cancelled" || enrollment.ValidateResolvedIdentityRenewal(*result, *request, target, f.source, at) != nil {
				t.Fatal("safe cancellation was not committed", err)
			}
			restarted, _ := NewStore(f.s.db, testMaster)
			restarted.renewalClock = func() time.Time { return at.Add(time.Second) }
			fresh := renewalResolutionProof(t, f, target, at.Add(time.Second))
			again, err := restarted.ResolveIdentityRenewal(t.Context(), *fresh)
			if err != nil || !reflect.DeepEqual(result, again) {
				t.Fatal("lost reply did not recover exact cancellation", err)
			}
			if !reflect.DeepEqual(before, renewalRetainedState(t, f.s)) {
				t.Fatal("cancellation changed identity, work, sessions or permanent key ownership")
			}
			var records, audits int
			if err := f.s.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_identity_renewal_cancellations),(SELECT count(*) FROM uem_agent_audit WHERE action='agent.identity.renew.cancel')`).Scan(&records, &audits); err != nil || records != 1 || audits != 1 {
				t.Fatal("cancellation retry duplicated effects", err)
			}
			if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); !errors.Is(err, ErrDenied) {
				t.Fatal("cancelled candidate activated", err)
			}
			freshPrepare, err := enrollment.NewRenewalRequest(f.source, f.current, f.candidate, f.request.RequestID, at)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.s.PrepareIdentityRenewal(t.Context(), *freshPrepare); !errors.Is(err, ErrDenied) {
				t.Fatal("cancelled preparation was replayed", err)
			}
			for _, statement := range []string{`DELETE FROM uem_agent_identity_renewal_cancellations`, `UPDATE uem_agent_identity_renewal_cancellations SET cancelled_at=cancelled_at`, `TRUNCATE uem_agent_identity_renewal_cancellations`} {
				if _, err := f.s.db.Exec(statement); err == nil {
					t.Fatal("permanent cancellation was mutable")
				}
			}
			_, token := invite(t, f.s, Scope{TenantID: 2, SiteID: 2}, 1)
			if _, err := f.s.Claim(t.Context(), *proof(t, token, f.candidate)); !errors.Is(err, ErrDenied) {
				t.Fatal("cancelled candidate keys were reassigned", err)
			}
			// A distinct signed attempt may use the same still-owned keypair, but
			// receives a distinct certificate; the cancelled certificate stays dead.
			freshPrepare, err = enrollment.NewRenewalRequest(f.source, f.current, f.candidate, uuid.NewString(), at)
			if err != nil {
				t.Fatal(err)
			}
			p, err := f.s.PrepareIdentityRenewal(t.Context(), *freshPrepare)
			if err != nil || p.Response.Certificate == f.response.Certificate {
				t.Fatal("cancelled attempt prevented new preparation", err)
			}
			newTarget, err := enrollment.ValidatePreparedIdentityRenewal(*p, *freshPrepare, f.source, at)
			if err != nil {
				t.Fatal(err)
			}
			newConfirm, err := enrollment.NewRenewalConfirmation(*newTarget, f.candidate, at)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *newConfirm); err != nil {
				t.Fatal("new attempt could not activate", err)
			}
			if _, err := f.s.ResolveIdentityRenewal(t.Context(), *request); !errors.Is(err, ErrDenied) {
				t.Fatal("old cancellation rolled back later generation", err)
			}
		})
	}
}

func TestIdentityRenewalResolutionRecoversConfirmedOutcomeAfterSourceExpiry(t *testing.T) {
	f := newIdentityRenewalFixture(t)
	_, target, confirm := f.prepareConfirmation(t)
	committed, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm)
	if err != nil {
		t.Fatal(err)
	}
	before := renewalRetainedState(t, f.s)
	later := f.now.Add(21 * 24 * time.Hour)
	restarted, _ := NewStore(f.s.db, testMaster)
	restarted.renewalClock = func() time.Time { return later }
	request := renewalResolutionProof(t, f, target, later)
	for range 2 {
		result, err := restarted.ResolveIdentityRenewal(t.Context(), *request)
		if err != nil || result.Outcome != "confirmed" || !result.ResolvedAt.Equal(committed.ConfirmedAt) || enrollment.ValidateResolvedIdentityRenewal(*result, *request, target, f.source, later) != nil {
			t.Fatal("confirmed resolution lost original activation evidence", err)
		}
	}
	if !reflect.DeepEqual(before, renewalRetainedState(t, f.s)) {
		t.Fatal("confirmation recovery repeated state transitions")
	}
	var cancelled, audits int
	if err := f.s.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_identity_renewal_cancellations),(SELECT count(*) FROM uem_agent_audit WHERE action='agent.identity.renew.cancel')`).Scan(&cancelled, &audits); err != nil || cancelled != 0 || audits != 0 {
		t.Fatal("confirmed outcome also cancelled candidate", err)
	}
}

func TestIdentityRenewalResolutionAndConfirmationHaveOneDurableWinner(t *testing.T) {
	for range 4 {
		f := newIdentityRenewalFixture(t)
		_, target, confirm := f.prepareConfirmation(t)
		request := renewalResolutionProof(t, f, target, f.now)
		var wg sync.WaitGroup
		var confirmed *ConfirmedIdentityRenewal
		var confirmErr error
		results := make(chan *ResolvedIdentityRenewal, 4)
		failures := make(chan error, 4)
		wg.Go(func() { confirmed, confirmErr = f.s.ConfirmIdentityRenewal(t.Context(), *confirm) })
		for range 4 {
			wg.Go(func() {
				r, err := f.s.ResolveIdentityRenewal(t.Context(), *request)
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
		if confirmErr != nil && !errors.Is(confirmErr, ErrDenied) {
			t.Fatal(confirmErr)
		}
		var first *ResolvedIdentityRenewal
		for r := range results {
			if first == nil {
				first = r
			} else if !reflect.DeepEqual(first, r) {
				t.Fatal("concurrent resolutions disagreed")
			}
			if (r.Outcome == "confirmed") != (confirmed != nil) {
				t.Fatal("cancellation and confirmation both won")
			}
		}
		var count int
		if first == nil {
			t.Fatal("no resolution outcome")
		}
		if err := f.s.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_identity_renewal_cancellations)+(SELECT count(*) FROM uem_agent_identity_renewal_confirmations)`).Scan(&count); err != nil || count != 1 {
			t.Fatal("race omitted or duplicated decision", err)
		}
	}
}

func TestIdentityRenewalResolutionDeniesRetiredRevokedExpiredOrForeignAuthority(t *testing.T) {
	for _, mutation := range []string{"source expired", "revoked", "site", "origin", "proof", "unknown request"} {
		t.Run(mutation, func(t *testing.T) {
			f := newIdentityRenewalFixture(t)
			_, target, _ := f.prepareConfirmation(t)
			at := f.now
			switch mutation {
			case "source expired":
				at = at.Add(21 * 24 * time.Hour)
			case "revoked":
				if err := f.s.RevokeIdentity(t.Context(), Scope{TenantID: 1, SiteID: 1}, f.source.DeviceID, "test-admin"); err != nil {
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
			case "unknown request":
				target.RequestID = uuid.NewString()
			}
			f.s.renewalClock = func() time.Time { return at }
			request := renewalResolutionProof(t, f, target, at)
			if mutation == "proof" {
				request.BrokerProof = f.request.CandidateBrokerProof
			}
			if result, err := f.s.ResolveIdentityRenewal(t.Context(), *request); !errors.Is(err, ErrDenied) || result != nil {
				t.Fatal("unauthorized resolution released outcome", err)
			}
			var count int
			if err := f.s.db.QueryRow(`SELECT count(*) FROM uem_agent_identity_renewal_cancellations`).Scan(&count); err != nil || count != 0 {
				t.Fatal("denied resolution changed state", err)
			}
		})
	}
}

func TestIdentityRenewalResolutionPreservesUnresolvedRecoveryWork(t *testing.T) {
	for _, readOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "uncertain rotation", true: "delivered read-only task"}[readOnly], func(t *testing.T) {
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
			_, target, confirm := f.prepareConfirmation(t)
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
			if readOnly {
				testQueueRecovery(t, f.s, access, identity, recipient)
				if _, err := access.HandleRecovery(t.Context(), *identity, enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "poll", RecipientID: recipient.ID}); err != nil {
					t.Fatal(err)
				}
			} else {
				task = rf.queue(t)
				if _, err := access.HandleRotation(t.Context(), *identity, rf.pollRequest()); err != nil {
					t.Fatal(err)
				}
				if _, err := access.HandleRotation(t.Context(), *identity, rf.result(t, task.Context, "uncertain")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); !errors.Is(err, ErrRenewalRecoveryPending) {
				t.Fatal("unreconciled work allowed handoff", err)
			}
			before := renewalRetainedState(t, f.s)
			request := renewalResolutionProof(t, f, target, f.now)
			if result, err := f.s.ResolveIdentityRenewal(t.Context(), *request); err != nil || result.Outcome != "cancelled" {
				t.Fatal("uncertain work prevented safe cancellation", err)
			}
			if !reflect.DeepEqual(before, renewalRetainedState(t, f.s)) {
				t.Fatal("safe cancellation changed recovery recipient, task or receipt")
			}
			if _, err := access.AuthenticateCertificate(t.Context(), identity.ID, cert); err != nil {
				t.Fatal("old certificate cannot reconcile retained work", err)
			}
			if task != nil {
				if _, err := access.HandleRotation(t.Context(), *identity, rf.result(t, task.Context, "uncertain")); err != nil {
					t.Fatal("retained receipt cannot be retried", err)
				}
			}
		})
	}
}

func TestIdentityRenewalResolutionRollsBackAuditFailureAndClockChanges(t *testing.T) {
	for _, mode := range []string{"audit", "expired proof", "expired source", "backward clock"} {
		t.Run(mode, func(t *testing.T) {
			f := newIdentityRenewalFixture(t)
			_, target, confirm := f.prepareConfirmation(t)
			at := f.now
			if mode == "expired source" {
				source, _ := x509.ParseCertificate(f.source.Certificate)
				at = source.NotAfter.Add(-time.Second)
			}
			request := renewalResolutionProof(t, f, target, at)
			if mode == "audit" {
				if _, err := f.s.db.Exec(`CREATE FUNCTION reject_resolution_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='agent.identity.renew.cancel' THEN RAISE EXCEPTION 'synthetic cancellation audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_resolution_audit BEFORE INSERT ON uem_agent_audit FOR EACH ROW EXECUTE FUNCTION reject_resolution_audit()`); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			f.s.renewalClock = func() time.Time {
				calls++
				if calls >= 3 {
					switch mode {
					case "expired proof":
						return at.Add(enrollment.RenewalProofLifetime + time.Second)
					case "expired source":
						return at.Add(time.Second)
					case "backward clock":
						return at.Add(-time.Microsecond)
					}
				}
				return at
			}
			before := renewalRetainedState(t, f.s)
			if result, err := f.s.ResolveIdentityRenewal(t.Context(), *request); err == nil || result != nil {
				t.Fatal("uncommitted cancellation released fallback")
			}
			var count int
			if err := f.s.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_identity_renewal_cancellations)+(SELECT count(*) FROM uem_agent_audit WHERE action='agent.identity.renew.cancel')`).Scan(&count); err != nil || count != 0 || !reflect.DeepEqual(before, renewalRetainedState(t, f.s)) {
				t.Fatal("failed resolution retained cancellation state", err)
			}
			if mode == "audit" {
				if _, err := f.s.db.Exec(`DROP TRIGGER reject_resolution_audit ON uem_agent_audit`); err != nil {
					t.Fatal(err)
				}
			}
			f.s.renewalClock = func() time.Time { return f.now }
			if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); err != nil {
				t.Fatal("rolled-back cancellation disabled candidate", err)
			}
		})
	}
}

func TestIdentityRenewalCancellationDatabaseGuardsRejectOldWriters(t *testing.T) {
	for _, isolation := range []sql.IsolationLevel{sql.LevelReadCommitted, sql.LevelRepeatableRead, sql.LevelSerializable} {
		t.Run(isolation.String(), func(t *testing.T) {
			f := newIdentityRenewalFixture(t)
			_, target, confirm := f.prepareConfirmation(t)
			request := renewalResolutionProof(t, f, target, f.now)
			// Model an older server which read prepared issuance before this new server
			// cancelled it. Its UPDATE is already waiting on our identity row lock when
			// cancellation commits, so a command-start snapshot alone is insufficient.
			cancelling, err := f.s.db.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer cancelling.Rollback()
			if _, err := loadIdentityRenewalCurrent(t.Context(), cancelling, f.source.DeviceID); err != nil {
				t.Fatal(err)
			}
			record := identityRenewalCancellationRecord{Version: 1, Request: *request, CancelledAt: f.now}
			plain, _ := json.Marshal(record)
			sealed, err := f.s.seal(plain, identityRenewalCancellationPurpose(f.source.DeviceID, request.RequestID))
			clear(plain)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cancelling.Exec(`INSERT INTO uem_agent_identity_renewal_cancellations(id,device_id,source_certificate_hash,certificate_hash,encrypted_record,cancelled_at) VALUES($1,$2,$3,$4,$5,$6)`, request.RequestID, request.DeviceID, request.SourceCertificateHash, request.CertificateHash, sealed, f.now); err != nil {
				t.Fatal(err)
			}
			old, err := f.s.db.BeginTx(t.Context(), &sql.TxOptions{Isolation: isolation})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { cancelling.Rollback(); old.Rollback() }()
			var pid int
			if err := old.QueryRow(`SELECT pg_backend_pid() FROM uem_agent_identities WHERE id=$1`, request.DeviceID).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := old.Exec(`UPDATE uem_agent_identities SET certificate_hash=$2,certificate=$3 WHERE id=$1`, f.source.DeviceID, request.CertificateHash, target.Candidate.Certificate)
				done <- err
			}()
			deadline := time.NewTimer(5 * time.Second)
			defer deadline.Stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for blocked := false; !blocked; {
				if err := f.s.db.QueryRow(`SELECT cardinality(pg_blocking_pids($1))>0`, pid).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if !blocked {
					select {
					case <-ticker.C:
					case <-deadline.C:
						t.Fatal("old writer did not wait for cancellation lock")
					}
				}
			}
			if err := cancelling.Commit(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("in-flight old writer activated permanently cancelled certificate")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("old writer did not stop")
			}
			old.Rollback()
			for _, statement := range []string{
				`UPDATE uem_agent_identities SET certificate_hash=$1`,
				`INSERT INTO uem_agent_identity_renewal_confirmations(id,device_id,certificate_hash,encrypted_record,confirmed_at) SELECT id,device_id,certificate_hash,encrypted_record,cancelled_at FROM uem_agent_identity_renewal_cancellations WHERE certificate_hash=$1`,
			} {
				if _, err := f.s.db.Exec(statement, confirm.CertificateHash); err == nil {
					t.Fatal("old writer bypassed permanent cancellation")
				}
			}
			if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); !errors.Is(err, ErrDenied) {
				t.Fatal("current writer ignored cancellation", err)
			}
			result, err := f.s.ResolveIdentityRenewal(t.Context(), *request)
			if err != nil || result.Outcome != "cancelled" {
				t.Fatal("blocked old writer damaged cancellation evidence", err)
			}
		})
	}
}
