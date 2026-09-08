package registry

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
)

const testMaster = "isolated-agent-registry-test-master-key"

func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("AGENT_ENROLLMENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set AGENT_ENROLLMENT_TEST_DATABASE_URL for isolated PostgreSQL tests")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "agent_registry_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	db.SetMaxOpenConns(16)
	if _, err = db.Exec(`CREATE TABLE tenants(id BIGINT PRIMARY KEY); CREATE TABLE sites(id BIGINT PRIMARY KEY,tenant_sites BIGINT NOT NULL REFERENCES tenants(id)); INSERT INTO tenants VALUES(1),(2); INSERT INTO sites VALUES(1,1),(2,2),(3,1)`); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(db, testMaster)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = s.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range []int{1, 2} {
		if _, err = s.EnsureAuthority(context.Background(), tenant, "Test organization", "https://uem.example.test", "test-admin", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func invite(t *testing.T, s *Store, scope Scope, uses int) (*Invitation, string) {
	t.Helper()
	i, err := s.Invite(context.Background(), InvitationOptions{Scope: scope, Platform: "windows", Architecture: "amd64", MaxUses: uses, ExpiresAt: time.Now().Add(time.Hour)}, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	return i, i.URL[strings.LastIndex(i.URL, "/")+1:]
}

func proof(t *testing.T, token string, keys *enrollment.Keys) *enrollment.Request {
	t.Helper()
	r, err := keys.Request(token, "windows", "amd64", "Test endpoint")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestConcurrentClaimsUseOneIdentityAndPreserveScopeAndLocalKeys(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	invitation, token := invite(t, s, Scope{TenantID: 1, SiteID: 1}, 1)
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	request := proof(t, token, keys)
	// A valid proof may request an administrator subject or arbitrary SANs.
	// The issuer must discard those names and reconstruct only the device ID.
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "openuem", Organization: []string{"Other organization"}}, DNSNames: []string{"admin.example.test"}}, keys.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	request.CSR = base64.StdEncoding.EncodeToString(csr)
	request.Proof = ""
	payload, _ := json.Marshal(request)
	hash := sha256.Sum256(payload)
	signature, err := keys.Broker.Sign(append([]byte("openuem/agent/enrollment/v1\x00"), hash[:]...))
	if err != nil {
		t.Fatal(err)
	}
	request.Proof = base64.RawURLEncoding.EncodeToString(signature)
	responses := make(chan *enrollment.Response, 12)
	failures := make(chan error, 12)
	var jobs sync.WaitGroup
	for range 12 {
		jobs.Go(func() {
			r, err := s.Claim(ctx, *request)
			if err != nil {
				failures <- err
			} else {
				responses <- r
			}
		})
	}
	jobs.Wait()
	close(responses)
	close(failures)
	for err := range failures {
		t.Fatal("concurrent retry failed", err)
	}
	var result *enrollment.Response
	for response := range responses {
		if result == nil {
			result = response
		} else if !reflect.DeepEqual(result, response) {
			t.Fatal("retry changed individual identity or certificate")
		}
	}
	if result == nil || result.TenantID != 1 || result.SiteID != 1 || result.Endpoint != "wss://uem.example.test/agent-channel" {
		t.Fatal("invitation scope was not authoritative")
	}
	if _, err := enrollment.ValidateResponse(*result, "https://uem.example.test", &keys.Certificate.PublicKey, time.Now()); err != nil {
		t.Fatal("native client rejected the real registry's issued response", err)
	}
	block, _ := pem.Decode([]byte(result.Certificate))
	if block == nil {
		t.Fatal("missing public certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !keys.Certificate.PublicKey.Equal(certificate.PublicKey) || certificate.IsCA || certificate.Subject.CommonName != result.DeviceID || len(certificate.Subject.Organization) != 0 || len(certificate.DNSNames) != 0 || len(certificate.URIs) != 1 || certificate.URIs[0].String() != "urn:openuem:agent:"+result.DeviceID || time.Until(certificate.NotAfter) > 90*24*time.Hour {
		t.Fatal("certificate did not bind endpoint key to server-selected identity")
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "PRIVATE KEY") {
		t.Fatal("response contains a private key")
	}
	var uses, count int
	if err = s.db.QueryRow(`SELECT uses FROM uem_agent_invitations WHERE id=$1`, invitation.ID).Scan(&uses); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_agent_identities`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if uses != 1 || count != 1 {
		t.Fatalf("retry consumed %d uses and created %d identities", uses, count)
	}
	restarted, _ := NewStore(s.db, testMaster)
	retried, err := restarted.Claim(ctx, *proof(t, token, keys))
	if err != nil || !reflect.DeepEqual(result, retried) {
		t.Fatal("restart/new CSR could not recover the same identity", err)
	}
	otherKeys, _ := enrollment.GenerateKeys()
	if _, err = s.Claim(ctx, *proof(t, token, otherKeys)); !errors.Is(err, ErrNotFound) {
		t.Fatal("exhausted invitation issued another identity", err)
	}
	otherInvitation, otherToken := invite(t, s, Scope{TenantID: 2, SiteID: 2}, 1)
	if _, err = s.Claim(ctx, *proof(t, otherToken, keys)); !errors.Is(err, ErrDenied) {
		t.Fatal("existing key rebound to another scope", err)
	}
	if err = s.db.QueryRow(`SELECT uses FROM uem_agent_invitations WHERE id=$1`, otherInvitation.ID).Scan(&uses); err != nil || uses != 0 {
		t.Fatal("failed issuance consumed another organization's invitation", err)
	}
	access, _ := NewAccessStore(s.db)
	active, err := access.AuthenticateCertificate(ctx, result.DeviceID, certificate)
	if err != nil || active.TenantID != 1 || active.SiteID != 1 {
		t.Fatal("issued identity did not authenticate", err)
	}
	if err = s.RevokeIdentity(ctx, Scope{TenantID: 2}, result.DeviceID, "other-admin"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign organization revoked device", err)
	}
	if err = s.RevokeIdentity(ctx, Scope{TenantID: 1, SiteID: 3}, result.DeviceID, "site-admin"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign site revoked device", err)
	}
	if err = s.RevokeIdentity(ctx, Scope{TenantID: 1}, result.DeviceID, "test-admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = access.AuthenticateCertificate(ctx, result.DeviceID, certificate); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked certificate authenticated", err)
	}
	if _, err = s.Claim(ctx, *request); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked identity recovered through retry", err)
	}
}

func TestInvitationsEnforceTargetExpiryRevocationAndAuthorityEncryption(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	keys, _ := enrollment.GenerateKeys()
	i, token := invite(t, s, Scope{TenantID: 1, SiteID: 1}, 2)
	wrong, err := keys.Request(token, "macos", "arm64", "Wrong target")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Claim(ctx, *wrong); !errors.Is(err, ErrNotFound) {
		t.Fatal("invitation target changed", err)
	}
	var uses int
	if err = s.db.QueryRow(`SELECT uses FROM uem_agent_invitations WHERE id=$1`, i.ID).Scan(&uses); err != nil || uses != 0 {
		t.Fatal("wrong target consumed a use", err)
	}
	var encrypted []byte
	if err = s.db.QueryRow(`SELECT encrypted_key FROM uem_agent_authorities WHERE tenant_id=1`).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encrypted), "PRIVATE KEY") {
		t.Fatal("CA key persisted in plaintext")
	}
	if _, err = s.open(encrypted, "2/authority/key"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("encrypted CA key could be moved to another organization", err)
	}
	wrongMaster, _ := NewStore(s.db, "different-isolated-test-master-key-32")
	if _, err = wrongMaster.Claim(ctx, *proof(t, token, keys)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("incorrect master key issued a credential", err)
	}
	if _, err = s.EnsureAuthority(ctx, 1, "Test organization", "https://attacker.example", "admin", nil, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("setup redirected existing organization", err)
	}
	if _, err = s.EnsureAuthority(ctx, 1, "Test organization", "https://uem.example.test", "admin", nil, nil); err != nil {
		t.Fatal("idempotent setup failed", err)
	}
	if err = s.RevokeInvitation(ctx, Scope{TenantID: 1}, i.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Claim(ctx, *proof(t, token, keys)); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked invitation issued a credential", err)
	}
	i, token = invite(t, s, Scope{TenantID: 1, SiteID: 1}, 1)
	if _, err = s.db.Exec(`UPDATE uem_agent_invitations SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=$1`, i.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Claim(ctx, *proof(t, token, keys)); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired invitation issued a credential", err)
	}
	_, token = invite(t, s, Scope{TenantID: 1, SiteID: 1}, 1)
	if _, err = s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Claim(ctx, *proof(t, token, keys)); !errors.Is(err, ErrNotFound) {
		t.Fatal("site move granted enrollment in a foreign organization", err)
	}
}

func TestBrokerSessionsAreRecordedAtomicallyWithRevocation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	_, token := invite(t, s, Scope{TenantID: 1, SiteID: 1}, 1)
	keys, _ := enrollment.GenerateKeys()
	response, err := s.Claim(ctx, *proof(t, token, keys))
	if err != nil {
		t.Fatal(err)
	}
	public, _ := keys.Broker.PublicKey()
	serverKey, _ := nkeys.CreateServer()
	serverID, _ := serverKey.PublicKey()
	access, _ := NewAccessStore(s.db)
	session := func(id uint64) enrollment.BrokerSession {
		return enrollment.BrokerSession{ServerID: serverID, ClientID: id, ExpiresAt: time.Now().Add(enrollment.BrokerLease)}
	}
	if _, err = access.AuthorizeDevice(ctx, public, session(1)); err != nil {
		t.Fatal("active key denied", err)
	}
	var jobs sync.WaitGroup
	failures := make(chan error, 33)
	start := make(chan struct{})
	for i := uint64(2); i < 34; i++ {
		jobs.Go(func() {
			<-start
			_, err := access.AuthorizeDevice(ctx, public, session(i))
			if err != nil && !errors.Is(err, ErrDenied) {
				failures <- err
			}
		})
	}
	jobs.Go(func() {
		<-start
		if err := s.RevokeIdentity(ctx, Scope{TenantID: 1}, response.DeviceID, "admin"); err != nil {
			failures <- err
		}
	})
	close(start)
	jobs.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	var orphaned int
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_agent_broker_sessions WHERE device_id=$1 AND disconnect_at IS NULL`, response.DeviceID).Scan(&orphaned); err != nil || orphaned != 0 {
		t.Fatal("revocation missed a concurrent grant", orphaned, err)
	}
	if _, err = access.AuthorizeDevice(ctx, public, session(99)); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked key reauthorized", err)
	}
	if _, err = access.ActiveIdentity(ctx, response.DeviceID); !errors.Is(err, ErrDenied) {
		t.Fatal("worker still accepted revoked identity", err)
	}
	batch, err := access.PendingDisconnects(ctx, 100)
	if err != nil || len(batch) < 1 {
		t.Fatal("revocation did not persist disconnect work", err)
	}
	for _, item := range batch {
		if item.ServerID != serverID || item.ClientID == 0 || time.Until(item.ExpiresAt) > enrollment.BrokerLease {
			t.Fatal("invalid persisted session")
		}
	}
	if repeated, err := access.PendingDisconnects(ctx, 100); err != nil || len(repeated) != 0 {
		t.Fatal("same batch immediately leased twice", err)
	}
	if _, err = s.db.Exec(`UPDATE uem_agent_broker_sessions SET attempted_at=clock_timestamp()-INTERVAL '6 seconds'`); err != nil {
		t.Fatal(err)
	}
	restarted, _ := NewAccessStore(s.db)
	if repeated, err := restarted.PendingDisconnects(ctx, 100); err != nil || len(repeated) != len(batch) {
		t.Fatal("disconnect retry lost across restart", err)
	}
	// An older batch becoming retryable must not starve sessions that have
	// never been attempted, even when the polling interval equals the lease.
	if _, err = s.db.Exec(`UPDATE uem_agent_broker_sessions SET attempted_at=clock_timestamp()-INTERVAL '6 seconds'`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO uem_agent_broker_sessions(server_id,client_id,device_id,expires_at,disconnect_at) SELECT $1,n,$2,clock_timestamp()+INTERVAL '1 minute',clock_timestamp() FROM generate_series(100,139) n`, serverID, response.DeviceID); err != nil {
		t.Fatal(err)
	}
	fresh, err := restarted.PendingDisconnects(ctx, 32)
	if err != nil || len(fresh) != 32 {
		t.Fatal("disconnect batch was not bounded", err)
	}
	for _, session := range fresh {
		if session.ClientID < 100 {
			t.Fatal("retryable sessions starved unattempted disconnects")
		}
	}
	if _, err = s.db.Exec(`UPDATE uem_agent_broker_sessions SET expires_at=clock_timestamp()-INTERVAL '1 second'`); err != nil {
		t.Fatal(err)
	}
	if err = access.CleanExpiredSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_agent_broker_sessions`).Scan(&orphaned); err != nil || orphaned != 0 {
		t.Fatal("expired sessions were not cleaned up", err)
	}
}
