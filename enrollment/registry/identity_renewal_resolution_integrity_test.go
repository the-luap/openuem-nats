package registry

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

func TestIdentityRenewalCancellationHistoryRequiresAuthenticatedMatchingIndexes(t *testing.T) {
	f := newIdentityRenewalFixture(t)
	_, target, confirm := f.prepareConfirmation(t)
	request := renewalResolutionProof(t, f, target, f.now)
	if _, err := f.s.ResolveIdentityRenewal(t.Context(), *request); err != nil {
		t.Fatal(err)
	}
	var original []byte
	if err := f.s.db.QueryRow(`SELECT encrypted_record FROM uem_agent_identity_renewal_cancellations WHERE id=$1`, request.RequestID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	next, err := enrollment.NewRenewalRequest(f.source, f.current, f.candidate, uuid.NewString(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{
		`UPDATE uem_agent_identity_renewal_cancellations SET encrypted_record=set_byte(encrypted_record,20,get_byte(encrypted_record,20)#1)`,
		`UPDATE uem_agent_identity_renewal_cancellations SET certificate_hash=repeat('a',64)`,
		`UPDATE uem_agent_identity_renewal_cancellations SET source_certificate_hash=repeat('a',64)`,
		`UPDATE uem_agent_identity_renewal_cancellations SET cancelled_at=cancelled_at+INTERVAL '1 microsecond'`,
	} {
		// The disposable schema owner alone simulates corruption; application
		// reads must authenticate history even when only skipping a pending block.
		if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_identity_renewal_cancellations DISABLE TRIGGER uem_agent_identity_renewal_cancellation_immutable`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec(mutation); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_identity_renewal_cancellations ENABLE TRIGGER uem_agent_identity_renewal_cancellation_immutable`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.ResolveIdentityRenewal(t.Context(), *request); !errors.Is(err, ErrUnavailable) {
			t.Fatal("corrupt cancellation authorized fallback", err)
		}
		if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); !errors.Is(err, ErrUnavailable) {
			t.Fatal("corrupt cancellation allowed confirmation", err)
		}
		for _, prepare := range []*enrollment.RenewalRequest{f.request, next} {
			if _, err := f.s.PrepareIdentityRenewal(t.Context(), *prepare); !errors.Is(err, ErrUnavailable) {
				t.Fatal("corrupt cancellation was skipped during preparation", err)
			}
		}
		if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_identity_renewal_cancellations DISABLE TRIGGER uem_agent_identity_renewal_cancellation_immutable`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec(`UPDATE uem_agent_identity_renewal_cancellations SET encrypted_record=$1,source_certificate_hash=$2,certificate_hash=$3,cancelled_at=$4`, original, request.SourceCertificateHash, request.CertificateHash, f.now); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_identity_renewal_cancellations ENABLE TRIGGER uem_agent_identity_renewal_cancellation_immutable`); err != nil {
			t.Fatal(err)
		}
	}
	wrong, _ := NewStore(f.s.db, "wrong-master-key-for-renewal-history-32-bytes")
	if _, err := wrong.ResolveIdentityRenewal(t.Context(), *request); !errors.Is(err, ErrUnavailable) {
		t.Fatal("resolution omitted key authentication", err)
	}
	// A valid encrypted confirmation together with cancellation is contradictory
	// evidence, even if an owner bypasses every ordinary insert guard.
	plain, _ := json.Marshal(identityRenewalConfirmationRecord{Version: 1, Request: *confirm, ConfirmedAt: f.now})
	sealed, err := f.s.seal(plain, identityRenewalConfirmationPurpose(request.DeviceID, request.RequestID))
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_identity_renewal_confirmations DISABLE TRIGGER uem_agent_identity_renewal_confirmation_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec(`INSERT INTO uem_agent_identity_renewal_confirmations(id,device_id,certificate_hash,encrypted_record,confirmed_at) VALUES($1,$2,$3,$4,$5)`, confirm.RequestID, confirm.DeviceID, confirm.CertificateHash, sealed, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_identity_renewal_confirmations ENABLE TRIGGER uem_agent_identity_renewal_confirmation_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.ResolveIdentityRenewal(t.Context(), *request); !errors.Is(err, ErrUnavailable) {
		t.Fatal("dual outcomes granted fallback", err)
	}
	if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); !errors.Is(err, ErrUnavailable) {
		t.Fatal("dual outcomes recovered activation", err)
	}
	if _, err := f.s.PrepareIdentityRenewal(t.Context(), *next); !errors.Is(err, ErrUnavailable) {
		t.Fatal("dual outcomes admitted next preparation", err)
	}
}

func TestIdentityRenewalCancellationCannotBeForgedForConfirmedOrDifferentIssuance(t *testing.T) {
	f := newIdentityRenewalFixture(t)
	_, target, confirm := f.prepareConfirmation(t)
	request := renewalResolutionProof(t, f, target, f.now)
	const insert = `INSERT INTO uem_agent_identity_renewal_cancellations(id,device_id,source_certificate_hash,certificate_hash,encrypted_record,cancelled_at) VALUES($1,$2,$3,$4,$5,$6)`
	for _, mode := range []string{"unknown request", "different source", "different candidate", "before issuance"} {
		id, source, candidate, at := request.RequestID, request.SourceCertificateHash, request.CertificateHash, f.now
		switch mode {
		case "unknown request":
			id = uuid.NewString()
		case "different source":
			source = candidate
		case "different candidate":
			candidate = source
		case "before issuance":
			at = at.Add(-time.Microsecond)
		}
		if _, err := f.s.db.Exec(insert, id, request.DeviceID, source, candidate, make([]byte, 29), at); err == nil {
			t.Fatal("database admitted mismatched cancellation", mode)
		}
	}
	if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec(insert, request.RequestID, request.DeviceID, request.SourceCertificateHash, request.CertificateHash, make([]byte, 29), f.now); err == nil {
		t.Fatal("database cancelled committed activation")
	}
	// Confirmed historical proof cannot resolve another current generation.
	later := f.now.Add(61 * 24 * time.Hour)
	f.s.renewalClock = func() time.Time { return later }
	next, err := enrollment.NewRenewalRequest(target.Candidate, f.candidate, f.candidate, uuid.NewString(), later)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.s.PrepareIdentityRenewal(t.Context(), *next)
	if err != nil {
		t.Fatal(err)
	}
	nextTarget, err := enrollment.ValidatePreparedIdentityRenewal(*prepared, *next, target.Candidate, later)
	if err != nil {
		t.Fatal(err)
	}
	nextConfirm, err := enrollment.NewRenewalConfirmation(*nextTarget, f.candidate, later)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *nextConfirm); err != nil {
		t.Fatal(err)
	}
	fresh := renewalResolutionProof(t, f, target, later)
	if _, err := f.s.ResolveIdentityRenewal(t.Context(), *fresh); !errors.Is(err, ErrDenied) {
		t.Fatal("historical resolution selected retired generation", err)
	}
}

func TestIdentityRenewalCancelledOutcomeDoesNotRestoreExpiredOrRevokedSource(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "revoked", true: "expired"}[expired], func(t *testing.T) {
			f := newIdentityRenewalFixture(t)
			_, target, _ := f.prepareConfirmation(t)
			request := renewalResolutionProof(t, f, target, f.now)
			if _, err := f.s.ResolveIdentityRenewal(t.Context(), *request); err != nil {
				t.Fatal(err)
			}
			at := f.now
			if expired {
				at = at.Add(21 * 24 * time.Hour)
			} else if err := f.s.RevokeIdentity(t.Context(), Scope{TenantID: 1, SiteID: 1}, f.source.DeviceID, "test-admin"); err != nil {
				t.Fatal(err)
			}
			f.s.renewalClock = func() time.Time { return at }
			request = renewalResolutionProof(t, f, target, at)
			if result, err := f.s.ResolveIdentityRenewal(t.Context(), *request); !errors.Is(err, ErrDenied) || result != nil {
				t.Fatal("retained cancellation resurrected old credentials", err)
			}
		})
	}
}
