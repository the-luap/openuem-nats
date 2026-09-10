package registry

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

func TestIdentityRenewalConcurrentDifferentRequestsAndEnrollmentKeyReservation(t *testing.T) {
	for _, raceClaim := range []bool{false, true} {
		t.Run(map[bool]string{false: "two preparations", true: "preparation and enrollment"}[raceClaim], func(t *testing.T) {
			f := newIdentityRenewalFixture(t)
			other, err := enrollment.NewRenewalRequest(f.source, f.current, f.candidate, uuid.NewString(), f.now)
			if err != nil {
				t.Fatal(err)
			}
			_, token := invite(t, f.s, Scope{TenantID: 2, SiteID: 2}, 1)
			claim := proof(t, token, f.candidate)
			var wg sync.WaitGroup
			results := make(chan error, 2)
			wg.Go(func() { _, err := f.s.PrepareIdentityRenewal(t.Context(), *f.request); results <- err })
			wg.Go(func() {
				if raceClaim {
					_, err := f.s.Claim(t.Context(), *claim)
					results <- err
				} else {
					_, err := f.s.PrepareIdentityRenewal(t.Context(), *other)
					results <- err
				}
			})
			wg.Wait()
			close(results)
			wins, denied := 0, 0
			for err := range results {
				if err == nil {
					wins++
				} else if errors.Is(err, ErrDenied) || (!raceClaim && errors.Is(err, ErrRenewalPending)) {
					denied++
				} else {
					t.Fatal("unexpected reservation race failure", err)
				}
			}
			if wins != 1 || denied != 1 {
				t.Fatal("racing keys obtained multiple owners or no winner", wins, denied)
			}
			var owners int
			if err := f.s.db.QueryRow(`SELECT count(DISTINCT device_id) FROM uem_agent_key_reservations WHERE kind='broker' AND key_value=$1`, f.request.BrokerKey).Scan(&owners); err != nil || owners != 1 {
				t.Fatal("candidate key ownership was not exclusive", err)
			}
		})
	}
}

func TestIdentityRenewalHistoryRequiresAuthenticPayloadAndMatchingIndexes(t *testing.T) {
	f := newIdentityRenewalFixture(t)
	_, _, confirm := f.prepareConfirmation(t)
	var encrypted []byte
	var certificateHash string
	var created time.Time
	if err := f.s.db.QueryRow(`SELECT encrypted_record,certificate_hash,created_at FROM uem_agent_identity_renewals WHERE id=$1`, f.request.RequestID).Scan(&encrypted, &certificateHash, &created); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{
		`UPDATE uem_agent_identity_renewals SET encrypted_record=set_byte(encrypted_record,20,get_byte(encrypted_record,20)#1)`,
		`UPDATE uem_agent_identity_renewals SET certificate_hash=repeat('a',64)`,
		`UPDATE uem_agent_identity_renewals SET created_at=created_at+INTERVAL '1 microsecond'`,
	} {
		// Only this test's disposable schema owner bypasses the ordinary immutable
		// guards to simulate corrupt storage. Application reads must still fail shut.
		if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_identity_renewals DISABLE TRIGGER uem_agent_identity_renewal_immutable`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec(mutation); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_identity_renewals ENABLE TRIGGER uem_agent_identity_renewal_immutable`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.PrepareIdentityRenewal(t.Context(), *f.request); !errors.Is(err, ErrUnavailable) {
			t.Fatal("corrupt preparation history was accepted", err)
		}
		if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); !errors.Is(err, ErrUnavailable) {
			t.Fatal("corrupt history activated a candidate", err)
		}
		if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_identity_renewals DISABLE TRIGGER uem_agent_identity_renewal_immutable`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec(`UPDATE uem_agent_identity_renewals SET encrypted_record=$1,certificate_hash=$2,created_at=$3`, encrypted, certificateHash, created); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_identity_renewals ENABLE TRIGGER uem_agent_identity_renewal_immutable`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow(`SELECT encrypted_record,confirmed_at FROM uem_agent_identity_renewal_confirmations WHERE id=$1`, f.request.RequestID).Scan(&encrypted, &created); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{
		`UPDATE uem_agent_identity_renewal_confirmations SET encrypted_record=set_byte(encrypted_record,20,get_byte(encrypted_record,20)#1)`,
		`UPDATE uem_agent_identity_renewal_confirmations SET certificate_hash=repeat('a',64)`,
		`UPDATE uem_agent_identity_renewal_confirmations SET confirmed_at=confirmed_at+INTERVAL '1 microsecond'`,
	} {
		if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_identity_renewal_confirmations DISABLE TRIGGER uem_agent_identity_renewal_confirmation_immutable`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec(mutation); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_identity_renewal_confirmations ENABLE TRIGGER uem_agent_identity_renewal_confirmation_immutable`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); !errors.Is(err, ErrUnavailable) {
			t.Fatal("corrupt confirmation history was accepted", err)
		}
		if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_identity_renewal_confirmations DISABLE TRIGGER uem_agent_identity_renewal_confirmation_immutable`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec(`UPDATE uem_agent_identity_renewal_confirmations SET encrypted_record=$1,certificate_hash=$2,confirmed_at=$3`, encrypted, certificateHash, created); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_identity_renewal_confirmations ENABLE TRIGGER uem_agent_identity_renewal_confirmation_immutable`); err != nil {
			t.Fatal(err)
		}
	}
	wrong, _ := NewStore(f.s.db, "wrong-master-key-for-renewal-history-32-bytes")
	if _, err := wrong.ConfirmIdentityRenewal(t.Context(), *confirm); !errors.Is(err, ErrUnavailable) {
		t.Fatal("confirmation bypassed recovery key authentication", err)
	}
	var hash string
	if err := f.s.db.QueryRow(`SELECT certificate_hash FROM uem_agent_identities WHERE id=$1`, f.source.DeviceID).Scan(&hash); err != nil || hash != confirm.CertificateHash {
		t.Fatal("corrupt retry changed current identity", err)
	}
}

func TestIdentityRenewalMigrationReservesExistingAndRetiredKeys(t *testing.T) {
	f := newIdentityRenewalFixture(t)
	// Restore the literal pre-renewal schema in this owned fixture, retaining its
	// actual issued device and all pre-existing registry/recovery tables.
	if _, err := f.s.db.Exec(`DROP TRIGGER uem_agent_identity_renewal_activation_guard ON uem_agent_identities; DROP TABLE uem_agent_identity_renewal_cancellations; DROP FUNCTION uem_agent_identity_renewal_cancellation_guard(); DROP FUNCTION uem_agent_identity_renewal_activation_guard(); DROP TABLE uem_agent_rotation_reconciliations; DROP TABLE uem_agent_rotation_recovery_checks; DROP TABLE uem_agent_identity_renewal_confirmations; DROP FUNCTION uem_agent_identity_renewal_confirmation_guard(); DROP TABLE uem_agent_identity_renewals; DROP TRIGGER uem_agent_identity_key_reservations ON uem_agent_identities; DROP TABLE uem_agent_key_reservations; DROP FUNCTION uem_agent_identity_key_reservations(); DROP FUNCTION uem_agent_renewal_immutable(); DELETE FROM uem_agent_migrations WHERE name IN ('migrations/007_identity_renewals.sql','migrations/008_identity_renewal_confirmations.sql','migrations/009_rotation_reconciliations.sql','migrations/010_identity_renewal_cancellations.sql','migrations/011_historical_rotation_checks.sql')`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := f.s.Migrate(t.Context()); err != nil {
			t.Fatal("existing registry could not upgrade idempotently", err)
		}
	}
	var count int
	if err := f.s.db.QueryRow(`SELECT count(*) FROM uem_agent_key_reservations WHERE device_id=$1`, f.source.DeviceID).Scan(&count); err != nil || count != 2 {
		t.Fatal("upgrade omitted existing key ownership", count, err)
	}
	_, _, confirm := f.prepareConfirmation(t)
	if _, err := f.s.ConfirmIdentityRenewal(t.Context(), *confirm); err != nil {
		t.Fatal("upgraded identity could not renew", err)
	}
	if err := f.s.db.QueryRow(`SELECT count(*) FROM uem_agent_key_reservations WHERE device_id=$1`, f.source.DeviceID).Scan(&count); err != nil || count != 4 {
		t.Fatal("renewal freed old keys", count, err)
	}
	_, token := invite(t, f.s, Scope{TenantID: 2, SiteID: 2}, 1)
	if _, err := f.s.Claim(t.Context(), *proof(t, token, f.current)); !errors.Is(err, ErrDenied) {
		t.Fatal("upgrade released historical keys for re-enrollment", err)
	}
}

func TestIdentityRenewalPreparationLifetimeUsesElapsedHoursAcrossDST(t *testing.T) {
	f := newIdentityRenewalFixture(t)
	tx, err := f.s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SET LOCAL TIME ZONE 'America/New_York'`); err != nil {
		t.Fatal(err)
	}
	// Spring clock change: seven local calendar days are only 167 elapsed hours.
	// The protocol's 168-hour maximum must remain independent of session timezone.
	created := time.Date(2026, 3, 7, 17, 0, 0, 0, time.UTC)
	const insert = `INSERT INTO uem_agent_identity_renewals(id,device_id,tenant_id,site_id,source_certificate_hash,certificate_hash,intent_digest,encrypted_record,created_at,expires_at) VALUES($1,$2,1,1,$3,$4,$3,$5,$6,$7)`
	if _, err := tx.Exec(insert, uuid.NewString(), f.source.DeviceID, strings.Repeat("a", 64), strings.Repeat("b", 64), make([]byte, 29), created, created.Add(168*time.Hour)); err != nil {
		t.Fatal("timezone rejected exact protocol lifetime", err)
	}
	if _, err := tx.Exec(insert, uuid.NewString(), f.source.DeviceID, strings.Repeat("a", 64), strings.Repeat("c", 64), make([]byte, 29), created, created.Add(168*time.Hour+time.Microsecond)); err == nil {
		t.Fatal("lifetime exceeded protocol maximum")
	}
}
