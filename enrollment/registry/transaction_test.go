package registry

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
)

func TestCallerTransactionAtomicallyBindsInvitationAndIssuance(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	options := InvitationOptions{Scope: Scope{TenantID: 1, SiteID: 1}, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	invitation, err := s.InviteInTransaction(ctx, tx, options, "console-admin")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a companion release-binding failure: no token, audit event or
	// invitation may survive the caller's rollback.
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_agent_invitations WHERE id=$1`, invitation.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("caller rollback retained an invitation", err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE resource_id=$1`, invitation.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("caller rollback retained a success audit event", err)
	}

	tx, err = s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	invitation, err = s.InviteInTransaction(ctx, tx, options, "console-admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	token := invitation.URL[strings.LastIndex(invitation.URL, "/")+1:]
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	request := proof(t, token, keys)
	tx, err = s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	rolledBack, err := s.ClaimInTransaction(ctx, tx, *request)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var uses int
	if err = s.db.QueryRow(`SELECT uses FROM uem_agent_invitations WHERE id=$1`, invitation.ID).Scan(&uses); err != nil || uses != 0 {
		t.Fatal("caller rollback consumed invitation capacity", err)
	}
	for _, table := range []string{"uem_agent_identities", "uem_agent_command_consumers", "uem_agent_audit"} {
		column := "id"
		if table == "uem_agent_command_consumers" {
			column = "device_id"
		}
		if table == "uem_agent_audit" {
			column = "resource_id"
		}
		if err = s.db.QueryRow(`SELECT count(*) FROM `+table+` WHERE `+column+`=$1`, rolledBack.DeviceID).Scan(&count); err != nil || count != 0 {
			t.Fatal("caller rollback retained issuance side effects", table, err)
		}
	}
	// Existing convenience APIs retain their own transaction and retry behavior.
	issued, err := s.Claim(ctx, *request)
	if err != nil || issued.DeviceID == rolledBack.DeviceID {
		t.Fatal("could not issue after rolled-back enrollment", err)
	}
	tx, err = s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	retry, err := s.ClaimInTransaction(ctx, tx, *request)
	if err != nil || retry.DeviceID != issued.DeviceID || retry.Certificate != issued.Certificate {
		t.Fatal("transactional retry changed the endpoint identity", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow(`SELECT uses FROM uem_agent_invitations WHERE id=$1`, invitation.ID).Scan(&uses); err != nil || uses != 1 {
		t.Fatal("transactional retry consumed additional capacity", err)
	}
}

func TestCallerTransactionDoesNotBypassProofOrScopeChecks(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, err := s.InviteInTransaction(ctx, nil, InvitationOptions{}, "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil invitation transaction accepted", err)
	}
	if _, err := s.ClaimInTransaction(ctx, nil, enrollment.Request{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil claim transaction accepted", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = s.InviteInTransaction(ctx, tx, InvitationOptions{Scope: Scope{TenantID: 1, SiteID: 2}, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatal("transaction bypassed site ownership", err)
	}
	if _, err = s.ClaimInTransaction(ctx, tx, enrollment.Request{}); err == nil {
		t.Fatal("transaction bypassed endpoint key proofs")
	}
}
