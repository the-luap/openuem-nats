package registry

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

func testMacHardware(t *testing.T, s *Store, scope Scope) (*AccessStore, *Identity, enrollment.HardwareInventory) {
	t.Helper()
	invite, err := s.Invite(t.Context(), InvitationOptions{Scope: scope, Platform: "macos", Architecture: "arm64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	token := invite.URL[strings.LastIndex(invite.URL, "/")+1:]
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	request, err := keys.Request(token, "macos", "arm64", "Mac")
	if err != nil {
		t.Fatal(err)
	}
	response, err := s.Claim(t.Context(), *request)
	if err != nil {
		t.Fatal(err)
	}
	access, _ := NewAccessStore(s.db)
	identity, err := access.ActiveIdentity(t.Context(), response.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	return access, identity, enrollment.HardwareInventory{Version: 1, AgentID: identity.ID, Model: "Mac16,1", Serial: "ABCD123456", PlatformUUID: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", ProvisioningUDID: "00006001-001234567890ABCD", Binding: &enrollment.MacBindingProof{ChallengeID: uuid.NewString(), DeviceID: uuid.NewString(), Token: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))}}
}

func TestHardwareEvidenceUsesFreshIdentityScopeAndHashedProof(t *testing.T) {
	s := testStore(t)
	access, identity, h := testMacHardware(t, s, Scope{TenantID: 1, SiteID: 1})
	if !access.HardwareReady(t.Context()) {
		t.Fatal("hardware schema unavailable")
	}
	if err := access.RecordHardware(t.Context(), *identity, h); err != nil {
		t.Fatal(err)
	}
	if err := access.RecordHardware(t.Context(), *identity, h); err != nil {
		t.Fatal(err)
	}
	var hash string
	var count int
	if err := s.db.QueryRow(`SELECT binding_token_hash FROM uem_agent_hardware WHERE device_id=$1`, identity.ID).Scan(&hash); err != nil || hash != digest([]byte(h.Binding.Token)) {
		t.Fatal("proof hash changed", err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE resource_id=$1 AND action='hardware.recorded'`, identity.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("unchanged observations inflated audit", count, err)
	}
	for _, mutate := range []func(*Identity){func(i *Identity) { i.TenantID = 2 }, func(i *Identity) { i.SiteID = 3 }, func(i *Identity) { i.Platform = "windows" }} {
		wrong := *identity
		mutate(&wrong)
		if err := access.RecordHardware(t.Context(), wrong, h); !errors.Is(err, ErrDenied) {
			t.Fatal("wrong scope accepted", err)
		}
	}
	otherAccess, other, otherHardware := testMacHardware(t, s, Scope{TenantID: 2, SiteID: 2})
	if err := otherAccess.RecordHardware(t.Context(), *other, h); !errors.Is(err, ErrDenied) {
		t.Fatal("foreign body identity accepted", err)
	}
	if err := otherAccess.RecordHardware(t.Context(), *other, otherHardware); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ALTER TABLE uem_agent_audit ADD CONSTRAINT hardware_audit_failure CHECK(action <> 'hardware.recorded')`); err == nil {
		t.Fatal("constraint unexpectedly accepted existing receipts")
	}
	if _, err := s.db.Exec(`ALTER TABLE uem_agent_audit ADD CONSTRAINT hardware_audit_failure CHECK(action <> 'hardware.recorded') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	changed := h
	changed.Serial = "NEW1234567"
	if err := access.RecordHardware(t.Context(), *identity, changed); err == nil {
		t.Fatal("hardware change committed without audit")
	}
	if _, err := s.db.Exec(`ALTER TABLE uem_agent_audit DROP CONSTRAINT hardware_audit_failure`); err != nil {
		t.Fatal(err)
	}
	var serial string
	if err := s.db.QueryRow(`SELECT serial FROM uem_agent_hardware WHERE device_id=$1`, identity.ID).Scan(&serial); err != nil || serial != h.Serial {
		t.Fatal("audit failure did not roll back evidence", err)
	}
	h.Binding = nil
	if err := access.RecordHardware(t.Context(), *identity, h); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM uem_agent_hardware WHERE device_id=$1 AND binding_token_hash IS NOT NULL`, identity.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("absent proof reused old association", err)
	}
	if err := s.RevokeIdentity(context.Background(), identity.Scope, identity.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := access.RecordHardware(t.Context(), *identity, h); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked identity updated hardware", err)
	}
	if _, err := s.db.Exec(`UPDATE uem_agent_hardware SET tenant_id=2 WHERE device_id=$1`, identity.ID); err == nil {
		t.Fatal("foreign hardware scope accepted")
	}
}

func TestHardwareEvidenceRechecksPersistedScopeExpiryAndConcurrentRevocation(t *testing.T) {
	s := testStore(t)
	access, identity, h := testMacHardware(t, s, Scope{TenantID: 1, SiteID: 1})
	for _, mutation := range []struct{ change, restore string }{
		{`UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=$1`, `UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()+INTERVAL '1 hour' WHERE id=$1`},
		{`UPDATE sites SET tenant_sites=2 WHERE id=1 AND $1::uuid IS NOT NULL`, `UPDATE sites SET tenant_sites=1 WHERE id=1 AND $1::uuid IS NOT NULL`},
	} {
		if _, err := s.db.Exec(mutation.change, identity.ID); err != nil {
			t.Fatal(err)
		}
		if err := access.RecordHardware(t.Context(), *identity, h); !errors.Is(err, ErrDenied) {
			t.Fatal("stale identity authorized hardware", err)
		}
		if _, err := s.db.Exec(mutation.restore, identity.ID); err != nil {
			t.Fatal(err)
		}
	}
	// Hold the exact identity row while revoking it. RecordHardware must wait
	// for the committed state, even though its caller holds an older identity.
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1`, identity.ID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- access.RecordHardware(t.Context(), *identity, h) }()
	select {
	case err := <-done:
		t.Fatal("hardware request bypassed locked identity", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrDenied) {
		t.Fatal("concurrent revocation did not prevent evidence", err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM uem_agent_hardware`).Scan(&count); err != nil || count != 0 {
		t.Fatal("denied request left evidence", err)
	}
}

func TestHardwareCertificateExpiryDuringRowLockWait(t *testing.T) {
	s := testStore(t)
	access, identity, h := testMacHardware(t, s, Scope{TenantID: 1, SiteID: 1})
	if _, err := s.db.Exec(`UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()+INTERVAL '200 milliseconds' WHERE id=$1`, identity.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var id string
	if err := tx.QueryRow(`SELECT id FROM uem_agent_identities WHERE id=$1 FOR UPDATE`, identity.ID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- access.RecordHardware(t.Context(), *identity, h) }()
	// Keep the row unchanged: PostgreSQL need not reevaluate its original
	// predicate when this lock is released, so the store must check time again.
	time.Sleep(250 * time.Millisecond)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrDenied) {
		t.Fatal("certificate expired while waiting but evidence was accepted", err)
	}
}
