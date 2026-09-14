package registry

import (
	"bytes"
	"crypto/x509"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
)

func linuxInvitation(t *testing.T, store *Store, scope Scope, architecture string) (*Invitation, string) {
	t.Helper()
	i, err := store.Invite(t.Context(), InvitationOptions{Scope: scope, Platform: "linux", Architecture: architecture, MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "owned-linux-administrator")
	if err != nil {
		t.Fatal(err)
	}
	return i, i.URL[strings.LastIndex(i.URL, "/")+1:]
}

func TestLinuxClaimsPreserveInvitationTargetScopeKeysAndRevocation(t *testing.T) {
	for _, architecture := range []string{"amd64", "arm64"} {
		t.Run(architecture, func(t *testing.T) {
			s := testStore(t)
			scope := Scope{TenantID: 1, SiteID: 1}
			invitation, token := linuxInvitation(t, s, scope, architecture)
			keys, err := enrollment.GenerateKeys()
			if err != nil {
				t.Fatal(err)
			}
			request, err := keys.Request(token, "linux", architecture, "Owned Linux endpoint")
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range [][2]string{{"windows", architecture}, {"macos", architecture}, {"linux", "amd64"}, {"linux", "arm64"}} {
				if target == [2]string{"linux", architecture} {
					continue
				}
				changed, err := keys.Request(token, target[0], target[1], request.DeviceName)
				if err != nil {
					t.Fatal(err)
				}
				if response, err := s.Claim(t.Context(), *changed); response != nil || !errors.Is(err, ErrNotFound) {
					t.Fatal("Linux invitation admitted another target", err)
				}
			}
			var results [4]*enrollment.Response
			var failures [4]error
			var joined sync.WaitGroup
			for i := range results {
				joined.Go(func() { results[i], failures[i] = s.Claim(t.Context(), *request) })
			}
			joined.Wait()
			for i := range results {
				if failures[i] != nil || results[i] == nil || !reflect.DeepEqual(results[0], results[i]) {
					t.Fatal("concurrent Linux claim lost its one complete identity", failures[i])
				}
			}
			response := results[0]
			if response.TenantID != scope.TenantID || response.SiteID != scope.SiteID {
				t.Fatal("Linux claim lost invitation scope")
			}
			if _, err := enrollment.ValidateResponse(*response, "https://uem.example.test", &keys.Certificate.PublicKey, time.Now()); err != nil {
				t.Fatal("Linux response lost endpoint key ownership", err)
			}
			var platform, cpu, broker string
			var uses, count int
			if err := s.db.QueryRow(`SELECT platform,architecture,broker_key FROM uem_agent_identities WHERE id=$1`, response.DeviceID).Scan(&platform, &cpu, &broker); err != nil || platform != "linux" || cpu != architecture || broker != request.BrokerKey {
				t.Fatal("Linux persisted identity lost target or broker key", err)
			}
			if err := s.db.QueryRow(`SELECT uses,(SELECT count(*) FROM uem_agent_identities WHERE invitation_id=$1) FROM uem_agent_invitations WHERE id=$1`, invitation.ID).Scan(&uses, &count); err != nil || uses != 1 || count != 1 {
				t.Fatal("Linux retries consumed multiple invitation uses", err)
			}
			_, foreignToken := linuxInvitation(t, s, Scope{TenantID: 1, SiteID: 3}, architecture)
			foreign, err := keys.Request(foreignToken, "linux", architecture, request.DeviceName)
			if err != nil {
				t.Fatal(err)
			}
			if other, err := s.Claim(t.Context(), *foreign); other != nil || !errors.Is(err, ErrDenied) {
				t.Fatal("Linux keys created another scoped identity", err)
			}
			if err := s.RevokeIdentity(t.Context(), scope, response.DeviceID, "owned-linux-administrator"); err != nil {
				t.Fatal(err)
			}
			if other, err := s.Claim(t.Context(), *request); other != nil || !errors.Is(err, ErrDenied) {
				t.Fatal("Linux replay bypassed revocation", err)
			}
		})
	}
}

func TestLinuxTargetMigrationRetainsExistingIdentityAndInvitation(t *testing.T) {
	s := testStore(t)
	i, token := invite(t, s, Scope{TenantID: 1, SiteID: 1}, 1)
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	response, err := s.Claim(t.Context(), *proof(t, token, keys))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func() []byte {
		t.Helper()
		var data []byte
		if err := s.db.QueryRow(`SELECT jsonb_build_object('identity',to_jsonb(d),'invitation',to_jsonb(i))::text FROM uem_agent_identities d JOIN uem_agent_invitations i ON i.id=d.invitation_id WHERE d.id=$1`, response.DeviceID).Scan(&data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	before := snapshot()
	if _, err := s.db.Exec(`ALTER TABLE uem_agent_invitations DROP CONSTRAINT uem_agent_invitations_platform_check, ADD CONSTRAINT uem_agent_invitations_platform_check CHECK(platform IN ('windows','macos')); ALTER TABLE uem_agent_identities DROP CONSTRAINT uem_agent_identities_platform_check, ADD CONSTRAINT uem_agent_identities_platform_check CHECK(platform IN ('windows','macos')); DELETE FROM uem_agent_migrations WHERE name='migrations/015_linux_identity_targets.sql'`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, snapshot()) {
			t.Fatal("Linux admission migration changed retained enrollment state")
		}
	}
	if again, err := s.Claim(t.Context(), *proof(t, token, keys)); err != nil || !reflect.DeepEqual(response, again) {
		t.Fatal("migration lost exact Windows recovery", err)
	}
	linuxInvitation(t, s, Scope{TenantID: 1, SiteID: 1}, "arm64")
	for _, platform := range []string{"freebsd", "Linux", ""} {
		_, err := s.db.Exec(`UPDATE uem_agent_invitations SET platform=$2 WHERE id=$1`, i.ID, platform)
		var state interface{ SQLState() string }
		if !errors.As(err, &state) || state.SQLState() != "23514" {
			t.Fatal("migration admitted an unsupported SQL platform", err)
		}
	}
}

func TestLinuxRenewalActivatesOnlyConfirmedCandidateAndRecoversAfterRestart(t *testing.T) {
	for _, architecture := range []string{"amd64", "arm64"} {
		t.Run(architecture, func(t *testing.T) {
			f := newTargetIdentityRenewalFixture(t, "linux", architecture)
			_, target, request := f.prepareConfirmation(t)
			access, err := NewAccessStore(f.s.db)
			if err != nil {
				t.Fatal(err)
			}
			oldCertificate, err := x509.ParseCertificate(f.source.Certificate)
			if err != nil {
				t.Fatal(err)
			}
			candidateCertificate, err := x509.ParseCertificate(target.Candidate.Certificate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := access.AuthenticateCertificate(t.Context(), f.source.DeviceID, oldCertificate); err != nil {
				t.Fatal("Linux preparation retired current certificate", err)
			}
			if _, err := access.AuthenticateCertificate(t.Context(), f.source.DeviceID, candidateCertificate); !errors.Is(err, ErrDenied) {
				t.Fatal("Linux preparation activated unconfirmed certificate", err)
			}
			confirmed, err := f.s.ConfirmIdentityRenewal(t.Context(), *request)
			if err != nil || confirmed.DeviceID != f.source.DeviceID || confirmed.CertificateHash != request.CertificateHash {
				t.Fatal("Linux confirmation lost exact identity", err)
			}
			if _, err := access.AuthenticateCertificate(t.Context(), f.source.DeviceID, oldCertificate); !errors.Is(err, ErrDenied) {
				t.Fatal("Linux confirmation retained old certificate", err)
			}
			identity, err := access.AuthenticateCertificate(t.Context(), f.source.DeviceID, candidateCertificate)
			if err != nil || identity.Platform != "linux" || identity.Architecture != architecture || identity.Scope != (Scope{TenantID: 1, SiteID: 1}) {
				t.Fatal("Linux candidate lost scoped platform identity", err)
			}
			server, err := nkeys.CreateServer()
			if err != nil {
				t.Fatal(err)
			}
			serverID, _ := server.PublicKey()
			server.Wipe()
			session := enrollment.BrokerSession{ServerID: serverID, ClientID: 1, ExpiresAt: time.Now().Add(enrollment.BrokerLease)}
			if _, err := access.AuthorizeDevice(t.Context(), f.source.BrokerKey, session); !errors.Is(err, ErrDenied) {
				t.Fatal("Linux retired broker key reconnected", err)
			}
			if broker, err := access.AuthorizeDevice(t.Context(), target.Candidate.BrokerKey, session); err != nil || broker.DeviceID != f.source.DeviceID {
				t.Fatal("Linux confirmed broker key could not reconnect", err)
			}
			restarted, err := NewStore(f.s.db, testMaster)
			if err != nil {
				t.Fatal(err)
			}
			later := f.now.Add(21 * 24 * time.Hour)
			restarted.renewalClock = func() time.Time { return later }
			fresh, err := enrollment.NewRenewalConfirmation(target, f.candidate, later)
			if err != nil {
				t.Fatal(err)
			}
			if again, err := restarted.ConfirmIdentityRenewal(t.Context(), *fresh); err != nil || !reflect.DeepEqual(confirmed, again) {
				t.Fatal("Linux restart lost committed handoff", err)
			}
			var count, confirmations int
			if err := f.s.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_identities),(SELECT count(*) FROM uem_agent_identity_renewal_confirmations)`).Scan(&count, &confirmations); err != nil || count != 1 || confirmations != 1 {
				t.Fatal("Linux renewal created another identity or handoff", err)
			}
		})
	}
}
