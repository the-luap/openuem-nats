package registry

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

func registryBurnPlan() enrollment.SoftwarePlan {
	p := softwarePlan()
	p.Kind, p.Artifact.Format = "windows-burn", "exe"
	p.Artifact.URL = "https://packages.example.test/owned.exe?token=private-burn"
	p.Arguments, p.MSIProperties = []string{"/quiet", "/norestart"}, nil
	p.Detection = enrollment.SoftwareDetection{Kind: "uninstall-key", UninstallKey: p.Detection.ProductCode, RegistryView: "64", Version: "1.2.3"}
	return p
}

func (f *softwareFixture) queueBurn(t *testing.T) (*enrollment.SoftwareTask, error) {
	t.Helper()
	tx, err := f.store.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	task, err := f.store.QueueSoftwareTaskInTransaction(t.Context(), tx, f.identity.Scope, f.identity.ID, uuid.NewString(), uuid.NewString(), uuid.NewString(), registryBurnPlan(), time.Now().Add(5*time.Minute), "operator")
	if err != nil {
		return nil, err
	}
	return task, tx.Commit()
}

func TestSoftwareBurnRegistryRequiresSignedCapabilityAndRetiresOldRecipient(t *testing.T) {
	f := newSoftwareFixture(t)
	if f.recipient.BurnVersion != 0 {
		t.Fatal("legacy recipient gained Burn capability")
	}
	if _, err := f.queueBurn(t); err == nil {
		t.Fatal("Burn task queued for legacy recipient")
	}
	pending := f.queue(t)
	oldID := f.recipient.ID
	challenge, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "challenge", PublicKey: f.key.PublicKey(), BurnVersion: 1})
	if err != nil || challenge.Registration == nil || challenge.Registration.BurnVersion != 1 || challenge.Recipient != nil {
		t.Fatal("capability upgrade did not require new signed registration", err)
	}
	assertStatus := func(want string) {
		t.Helper()
		var status string
		if err := f.store.db.QueryRow(`SELECT status FROM uem_agent_software_tasks WHERE id=$1`, pending.Context.TaskID).Scan(&status); err != nil || status != want {
			t.Fatal("capability transition changed task reservation", status, err)
		}
	}
	assertStatus("pending")
	if _, err := f.queueBurn(t); err == nil {
		t.Fatal("unsigned challenge enabled Burn delivery")
	}
	changed := *challenge.Registration
	changed.BurnVersion = 0
	signature, err := enrollment.SignSoftwareRegistration(changed, f.cert, f.signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "register", Registration: &changed, Signature: signature}); err == nil {
		t.Fatal("signed response changed the issued capability challenge")
	}
	assertStatus("pending")
	signature, err = enrollment.SignSoftwareRegistration(*challenge.Registration, f.cert, f.signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`CREATE FUNCTION reject_burn_registration_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='software.recipient.registered' THEN RAISE EXCEPTION 'owned audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_burn_registration_audit BEFORE INSERT ON uem_agent_audit FOR EACH ROW EXECUTE FUNCTION reject_burn_registration_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "register", Registration: challenge.Registration, Signature: signature}); err == nil {
		t.Fatal("capability escaped its required registration audit")
	}
	assertStatus("pending")
	var retainedID string
	var retainedVersion int
	if err := f.store.db.QueryRow(`SELECT id,burn_version FROM uem_agent_software_recipients WHERE device_id=$1`, f.identity.ID).Scan(&retainedID, &retainedVersion); err != nil || retainedID != oldID || retainedVersion != 0 {
		t.Fatal("failed audit changed capability", err)
	}
	if _, err := f.store.db.Exec(`DROP TRIGGER reject_burn_registration_audit ON uem_agent_audit`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		reply, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "register", Registration: challenge.Registration, Signature: signature})
		if err != nil || reply.Recipient == nil || reply.Recipient.BurnVersion != 1 || reply.Recipient.ID == oldID {
			t.Fatal("signed Burn registration or retry failed", err)
		}
		f.recipient = reply.Recipient
	}
	assertStatus("cancelled")
	var audits int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE action='software.recipient.registered' AND resource_id=$1`, f.recipient.ID).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("registration retry duplicated capability audit", err)
	}
	if _, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: oldID}); err == nil {
		t.Fatal("retired recipient remained authorized")
	}
	burn, err := f.queueBurn(t)
	if err != nil {
		t.Fatal("capable recipient could not receive Burn intent", err)
	}
	secret, err := f.key.Open(*burn, f.authority, f.recipient.Identity, f.recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	if secret.Plan.Kind != "windows-burn" || secret.Plan.Detection != registryBurnPlan().Detection {
		t.Fatal("registry lost encrypted Burn identity")
	}
	if reply, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID}); err != nil || reply.Task == nil {
		t.Fatal("registered Burn task was not delivered", err)
	}
	// A returning old agent receives the old wire grammar and must sign another
	// registration. The server never silently strips a capability from its key.
	downgrade, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "challenge", PublicKey: f.key.PublicKey()})
	if err != nil || downgrade.Registration == nil || downgrade.Registration.BurnVersion != 0 {
		t.Fatal("legacy agent cannot re-register", err)
	}
	wire, _ := json.Marshal(downgrade)
	if bytes.Contains(wire, []byte("burn_version")) {
		t.Fatal("capability leaked into legacy reply grammar")
	}
	signature, err = enrollment.SignSoftwareRegistration(*downgrade.Registration, f.cert, f.signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.call(t.Context(), enrollment.SoftwareRequest{Action: "register", Registration: downgrade.Registration, Signature: signature}); err != nil {
		t.Fatal(err)
	}
	var status string
	if err = f.store.db.QueryRow(`SELECT status FROM uem_agent_software_tasks WHERE id=$1`, burn.Context.TaskID).Scan(&status); err != nil || status != "uncertain" {
		t.Fatal("downgrade lost delivered Burn uncertainty", status, err)
	}
	if _, err := f.queueBurn(t); err == nil {
		t.Fatal("downgraded registration retained Burn authority")
	}
}

func TestSoftwareBurnMigrationPreservesExistingRecipientAndTask(t *testing.T) {
	f := newSoftwareFixture(t)
	task := f.queue(t)
	var before string
	if err := f.store.db.QueryRow(`SELECT to_jsonb(t)::text FROM uem_agent_software_tasks t WHERE id=$1`, task.Context.TaskID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`ALTER TABLE uem_agent_software_recipients DROP COLUMN burn_version; ALTER TABLE uem_agent_software_challenges DROP COLUMN burn_version; DELETE FROM uem_agent_migrations WHERE name='migrations/014_software_burn_capability.sql'`); err != nil {
		t.Fatal(err)
	}
	if f.access.SoftwareReady(t.Context()) {
		t.Fatal("missing capability schema advertised readiness")
	}
	for range 2 {
		if err := f.store.Migrate(t.Context()); err != nil {
			t.Fatal("existing recipient migration", err)
		}
	}
	var after string
	if err := f.store.db.QueryRow(`SELECT to_jsonb(t)::text FROM uem_agent_software_tasks t WHERE id=$1`, task.Context.TaskID).Scan(&after); err != nil || before != after || !f.access.SoftwareReady(t.Context()) {
		t.Fatal("migration changed retained task or stayed unavailable", err)
	}
	reply, err := f.call(t.Context(), enrollment.SoftwareRequest{Action: "challenge", PublicKey: f.key.PublicKey()})
	if err != nil || reply.Recipient == nil || reply.Recipient.BurnVersion != 0 || reply.Recipient.ID != f.recipient.ID {
		t.Fatal("migration replaced legacy recipient or inferred capability", err)
	}
	if _, err := f.store.db.Exec(`UPDATE uem_agent_software_recipients SET burn_version=2`); err == nil {
		t.Fatal("unknown capability stored")
	}
}
