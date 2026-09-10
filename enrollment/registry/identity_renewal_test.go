package registry

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

type identityRenewalFixture struct {
	s                  *Store
	source             enrollment.RenewalSource
	current, candidate *enrollment.Keys
	request            *enrollment.RenewalRequest
	response           *enrollment.Response
	now                time.Time
}

func newIdentityRenewalFixture(t *testing.T) *identityRenewalFixture {
	t.Helper()
	s := testStore(t)
	_, token := invite(t, s, Scope{TenantID: 1, SiteID: 1}, 1)
	current, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	issued, err := s.Claim(t.Context(), *proof(t, token, current))
	if err != nil {
		t.Fatal(err)
	}
	var certificate, issuer, encrypted []byte
	if err := s.db.QueryRow(`SELECT i.certificate,a.certificate,a.encrypted_key FROM uem_agent_identities i JOIN uem_agent_authorities a ON a.tenant_id=i.tenant_id WHERE i.id=$1`, issued.DeviceID).Scan(&certificate, &issuer, &encrypted); err != nil {
		t.Fatal(err)
	}
	private, err := s.open(encrypted, "1/authority/key")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	ca, signer, err := parseAuthority(issuer, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	leaf.NotAfter = now.Add(20 * 24 * time.Hour).Truncate(time.Second)
	leaf.SerialNumber, err = certificateSerial()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err = x509.CreateCertificate(rand.Reader, leaf, ca, &current.Certificate.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE uem_agent_identities SET certificate=$2,certificate_hash=$3,certificate_expires_at=$4 WHERE id=$1`, issued.DeviceID, certificate, digest(certificate), leaf.NotAfter); err != nil {
		t.Fatal(err)
	}
	candidate, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	broker, _ := current.Broker.PublicKey()
	source := enrollment.RenewalSource{DeviceID: issued.DeviceID, TenantID: 1, SiteID: 1, Origin: "https://uem.example.test", Platform: "windows", Architecture: "amd64", BrokerKey: broker, Certificate: certificate}
	request, err := enrollment.NewRenewalRequest(source, current, candidate, uuid.NewString(), now)
	if err != nil {
		t.Fatal(err)
	}
	s.renewalClock = func() time.Time { return now }
	return &identityRenewalFixture{s: s, source: source, current: current, candidate: candidate, request: request, response: publicResponse(issued.DeviceID, Scope{TenantID: 1, SiteID: 1}, source.Origin, certificate, issuer, leaf.NotAfter), now: now}
}

func TestIdentityRenewalPreparationPreservesCurrentIdentityAndExactRetries(t *testing.T) {
	f := newIdentityRenewalFixture(t)
	var before []byte
	if err := f.s.db.QueryRow(`SELECT row_to_json(i)::text FROM uem_agent_identities i WHERE id=$1`, f.source.DeviceID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan *PreparedIdentityRenewal, 8)
	failures := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			r, err := f.s.PrepareIdentityRenewal(t.Context(), *f.request)
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
	var first *PreparedIdentityRenewal
	for r := range results {
		if first == nil {
			first = r
		} else if !reflect.DeepEqual(first, r) {
			t.Fatal("concurrent retry issued another candidate")
		}
	}
	if first == nil || first.ID != f.request.RequestID || first.Response.DeviceID != f.source.DeviceID || first.SourceCertificateHash != digest(f.source.Certificate) {
		t.Fatal("candidate changed original identity")
	}
	candidate, err := enrollment.ValidateResponse(first.Response, f.source.Origin, &f.candidate.Certificate.PublicKey, f.now)
	if err != nil {
		t.Fatal(err)
	}
	var after []byte
	if err := f.s.db.QueryRow(`SELECT row_to_json(i)::text FROM uem_agent_identities i WHERE id=$1`, f.source.DeviceID).Scan(&after); err != nil || !bytes.Equal(before, after) {
		t.Fatal("preparation changed current identity", err)
	}
	access, _ := NewAccessStore(f.s.db)
	original, _ := x509.ParseCertificate(f.source.Certificate)
	if _, err := access.AuthenticateCertificate(t.Context(), f.source.DeviceID, original); err != nil {
		t.Fatal("preparation retired source certificate", err)
	}
	if _, err := access.AuthenticateCertificate(t.Context(), f.source.DeviceID, candidate); !errors.Is(err, ErrDenied) {
		t.Fatal("preparation activated candidate certificate", err)
	}
	var records, audits, reservations int
	if err := f.s.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_identity_renewals),(SELECT count(*) FROM uem_agent_audit WHERE action='agent.identity.renew.prepare'),(SELECT count(*) FROM uem_agent_key_reservations WHERE device_id=$1)`, f.source.DeviceID).Scan(&records, &audits, &reservations); err != nil || records != 1 || audits != 1 || reservations != 4 {
		t.Fatal("preparation duplicated evidence or omitted key ownership", records, audits, reservations, err)
	}
	restarted, err := NewStore(f.s.db, testMaster)
	if err != nil {
		t.Fatal(err)
	}
	restarted.renewalClock = func() time.Time { return f.now.Add(time.Second) }
	again, err := enrollment.NewRenewalRequest(f.source, f.current, f.candidate, f.request.RequestID, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.PrepareIdentityRenewal(t.Context(), *again)
	if err != nil || !reflect.DeepEqual(first, replayed) {
		t.Fatal("restart lost exact candidate retry", err)
	}
	wrong, _ := NewStore(f.s.db, "wrong-master-key-for-renewal-history-32-bytes")
	if _, err := wrong.PrepareIdentityRenewal(t.Context(), *again); !errors.Is(err, ErrUnavailable) {
		t.Fatal("pending issuance did not require its matching root key", err)
	}
	other, err := enrollment.NewRenewalRequest(f.source, f.current, f.candidate, uuid.NewString(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.PrepareIdentityRenewal(t.Context(), *other); !errors.Is(err, ErrRenewalPending) {
		t.Fatal("second pending issuance admitted", err)
	}
}

func TestIdentityRenewalReservationBlocksOtherEnrollmentsAndDirectReassignment(t *testing.T) {
	f := newIdentityRenewalFixture(t)
	if _, err := f.s.PrepareIdentityRenewal(t.Context(), *f.request); err != nil {
		t.Fatal(err)
	}
	_, token := invite(t, f.s, Scope{TenantID: 2, SiteID: 2}, 1)
	if _, err := f.s.Claim(t.Context(), *proof(t, token, f.candidate)); !errors.Is(err, ErrDenied) {
		t.Fatal("pending keys enrolled in another organization", err)
	}
	var uses, identities int
	if err := f.s.db.QueryRow(`SELECT (SELECT uses FROM uem_agent_invitations WHERE token_hash=$1),(SELECT count(*) FROM uem_agent_identities)`, digest([]byte(token))).Scan(&uses, &identities); err != nil || uses != 0 || identities != 1 {
		t.Fatal("denied key reuse consumed enrollment", err)
	}
	for _, statement := range []string{`DELETE FROM uem_agent_key_reservations`, `UPDATE uem_agent_key_reservations SET key_value=key_value`, `TRUNCATE uem_agent_key_reservations`, `DELETE FROM uem_agent_identity_renewals`, `UPDATE uem_agent_identity_renewals SET expires_at=expires_at`, `TRUNCATE uem_agent_identity_renewals`} {
		if _, err := f.s.db.Exec(statement); err == nil {
			t.Fatal("protected renewal evidence could be changed", statement)
		}
	}
}

func TestIdentityRenewalAuditRollbackDoesNotReserveOrIssueKeys(t *testing.T) {
	f := newIdentityRenewalFixture(t)
	if _, err := f.s.db.Exec(`CREATE FUNCTION reject_renewal_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='agent.identity.renew.prepare' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_renewal_audit BEFORE INSERT ON uem_agent_audit FOR EACH ROW EXECUTE FUNCTION reject_renewal_audit()`); err != nil {
		t.Fatal(err)
	}
	if r, err := f.s.PrepareIdentityRenewal(t.Context(), *f.request); err == nil || r != nil {
		t.Fatal("uncommitted candidate was released")
	}
	var records, reservations int
	if err := f.s.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_identity_renewals),(SELECT count(*) FROM uem_agent_key_reservations)`).Scan(&records, &reservations); err != nil || records != 0 || reservations != 2 {
		t.Fatal("audit rollback left candidate state", records, reservations, err)
	}
	if _, err := f.s.db.Exec(`DROP TRIGGER reject_renewal_audit ON uem_agent_audit`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.PrepareIdentityRenewal(t.Context(), *f.request); err != nil {
		t.Fatal("rolled-back preparation could not retry", err)
	}
}

func TestIdentityRenewalRejectsExpiredPreparationAndChangedAuthority(t *testing.T) {
	f := newIdentityRenewalFixture(t)
	if _, err := f.s.PrepareIdentityRenewal(t.Context(), *f.request); err != nil {
		t.Fatal(err)
	}
	later := f.now.Add(IdentityRenewalPreparationLifetime + time.Minute)
	f.s.renewalClock = func() time.Time { return later }
	expired, err := enrollment.NewRenewalRequest(f.source, f.current, f.candidate, f.request.RequestID, later)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.PrepareIdentityRenewal(t.Context(), *expired); !errors.Is(err, ErrDenied) {
		t.Fatal("expired preparation was revived", err)
	}
	newRequest, err := enrollment.NewRenewalRequest(f.source, f.current, f.candidate, uuid.NewString(), later)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.PrepareIdentityRenewal(t.Context(), *newRequest); err != nil {
		t.Fatal("expired preparation blocked a fresh authorized attempt", err)
	}
	if _, err := f.s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.PrepareIdentityRenewal(t.Context(), *newRequest); !errors.Is(err, ErrDenied) {
		t.Fatal("site move retained renewal authority", err)
	}
}

func TestIdentityRenewalNewEnrollmentIsNotDue(t *testing.T) {
	s := testStore(t)
	_, token := invite(t, s, Scope{TenantID: 1, SiteID: 1}, 1)
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Claim(t.Context(), *proof(t, token, keys))
	if err != nil {
		t.Fatal(err)
	}
	var cert []byte
	if err := s.db.QueryRow(`SELECT certificate FROM uem_agent_identities WHERE id=$1`, r.DeviceID).Scan(&cert); err != nil {
		t.Fatal(err)
	}
	broker, _ := keys.Broker.PublicKey()
	source := enrollment.RenewalSource{DeviceID: r.DeviceID, TenantID: 1, SiteID: 1, Origin: "https://uem.example.test", Platform: "windows", Architecture: "amd64", BrokerKey: broker, Certificate: cert}
	q, err := enrollment.NewRenewalRequest(source, keys, keys, uuid.NewString(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareIdentityRenewal(t.Context(), *q); !errors.Is(err, ErrRenewalNotDue) {
		t.Fatal("new certificate renewed outside due window", err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM uem_agent_identity_renewals`).Scan(&count); err != nil || count != 0 {
		t.Fatal("not-due request persisted issuance", err)
	}
}
