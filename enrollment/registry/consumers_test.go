package registry

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment"
)

type failConsumerAcknowledgment struct{ *AccessStore }

func (s failConsumerAcknowledgment) CompleteCommandConsumer(context.Context, enrollment.CommandConsumerWork) error {
	return errors.New("simulated post-broker database failure")
}

func TestDurableConsumerWorkReconcilesRealBrokerAfterUncertainCompletion(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	_, token := invite(t, s, Scope{TenantID: 1, SiteID: 1}, 1)
	keys, _ := enrollment.GenerateKeys()
	issued, err := s.Claim(ctx, *proof(t, token, keys))
	if err != nil {
		t.Fatal(err)
	}
	access, _ := NewAccessStore(s.db)
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("test broker did not start")
	}
	connection, err := nats.Connect(broker.ClientURL(), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	if err = openuem.ReconcileAgentCommandConsumers(ctx, js, failConsumerAcknowledgment{access}); err == nil {
		t.Fatal("uncertain database completion was accepted")
	}
	name, _ := enrollment.ConsumerName(issued.DeviceID)
	if _, err = js.Consumer(ctx, "AGENTS_STREAM", name); err != nil {
		t.Fatal("consumer creation did not reach broker", err)
	}
	if _, err = s.db.Exec(`UPDATE uem_agent_command_consumers SET attempted_at=clock_timestamp()-INTERVAL '31 seconds'`); err != nil {
		t.Fatal(err)
	}
	restarted, _ := NewAccessStore(s.db)
	if err = openuem.ReconcileAgentCommandConsumers(ctx, js, restarted); err != nil {
		t.Fatal("retry after uncertain completion did not converge", err)
	}
	if work, err := restarted.PendingCommandConsumers(ctx, 32); err != nil || len(work) != 0 {
		t.Fatal("retry did not acknowledge durable work", err)
	}
	if err = s.RevokeIdentity(ctx, Scope{TenantID: 1}, issued.DeviceID, "test-admin"); err != nil {
		t.Fatal(err)
	}
	if err = openuem.ReconcileAgentCommandConsumers(ctx, js, restarted); err != nil {
		t.Fatal("revocation consumer reconciliation failed", err)
	}
	if _, err = js.Consumer(ctx, "AGENTS_STREAM", name); !errors.Is(err, jetstream.ErrConsumerNotFound) {
		t.Fatal("revoked identity retained its consumer", err)
	}
	// Repeated deletion is harmless after broker data loss or an earlier success.
	if _, err = s.db.Exec(`UPDATE uem_agent_command_consumers SET attempted_at=NULL,reconcile_at=clock_timestamp()-INTERVAL '1 second'`); err != nil {
		t.Fatal(err)
	}
	if err = openuem.ReconcileAgentCommandConsumers(ctx, js, restarted); err != nil {
		t.Fatal("already-deleted consumer was not idempotent", err)
	}
}

func TestCommandConsumerWorkSurvivesRetriesRevocationAndStaleCompletion(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	_, token := invite(t, s, Scope{TenantID: 1, SiteID: 1}, 1)
	keys, _ := enrollment.GenerateKeys()
	issued, err := s.Claim(ctx, *proof(t, token, keys))
	if err != nil {
		t.Fatal(err)
	}
	access, _ := NewAccessStore(s.db)
	first, err := access.PendingCommandConsumers(ctx, 32)
	if err != nil || len(first) != 1 || first[0].DeviceID != issued.DeviceID || !first[0].Active {
		t.Fatal("issuance did not atomically queue command provisioning", err)
	}
	if again, err := access.PendingCommandConsumers(ctx, 32); err != nil || len(again) != 0 {
		t.Fatal("concurrent poll duplicated a current lease", err)
	}
	if _, err = s.db.Exec(`UPDATE uem_agent_command_consumers SET attempted_at=clock_timestamp()-INTERVAL '31 seconds'`); err != nil {
		t.Fatal(err)
	}
	restarted, _ := NewAccessStore(s.db)
	retry, err := restarted.PendingCommandConsumers(ctx, 32)
	if err != nil || len(retry) != 1 || retry[0].Revision != first[0].Revision || retry[0].LeaseID == first[0].LeaseID {
		t.Fatal("restart did not retry durable work with a fresh lease", err)
	}
	if err = restarted.CompleteCommandConsumer(ctx, retry[0]); err != nil {
		t.Fatal(err)
	}
	if pending, err := restarted.PendingCommandConsumers(ctx, 32); err != nil || len(pending) != 0 {
		t.Fatal("completed provisioning remained pending", err)
	}
	if err = s.RevokeIdentity(ctx, Scope{TenantID: 1}, issued.DeviceID, "admin"); err != nil {
		t.Fatal(err)
	}
	deletion, err := restarted.PendingCommandConsumers(ctx, 32)
	if err != nil || len(deletion) != 1 || deletion[0].Active || deletion[0].Revision <= first[0].Revision {
		t.Fatal("revocation did not atomically request consumer deletion", err)
	}
	if err = restarted.CompleteCommandConsumer(ctx, deletion[0]); err != nil {
		t.Fatal(err)
	}
	// An old broker creation may finish after the deletion. Its completion must
	// request another deletion, never acknowledge the old active state as current.
	if err = restarted.CompleteCommandConsumer(ctx, first[0]); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE uem_agent_command_consumers SET attempted_at=clock_timestamp()-INTERVAL '31 seconds'`); err != nil {
		t.Fatal(err)
	}
	deletion, err = restarted.PendingCommandConsumers(ctx, 32)
	if err != nil || len(deletion) != 1 || deletion[0].Active {
		t.Fatal("stale completion lost the newer desired deletion", err)
	}
	if err = restarted.CompleteCommandConsumer(ctx, deletion[0]); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE uem_agent_command_consumers SET reconcile_at=clock_timestamp()-INTERVAL '1 second',attempted_at=NULL`); err != nil {
		t.Fatal(err)
	}
	if check, err := restarted.PendingCommandConsumers(ctx, 32); err != nil || len(check) != 1 || check[0].Active {
		t.Fatal("periodic reconciliation was not scheduled", err)
	}
}

func TestCommandConsumersReactToScopeChangesAndExpiry(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	_, token := invite(t, s, Scope{TenantID: 1, SiteID: 1}, 1)
	keys, _ := enrollment.GenerateKeys()
	issued, err := s.Claim(ctx, *proof(t, token, keys))
	if err != nil {
		t.Fatal(err)
	}
	access, _ := NewAccessStore(s.db)
	work, err := access.PendingCommandConsumers(ctx, 1)
	if err != nil || len(work) != 1 {
		t.Fatal(err)
	}
	if err = access.CompleteCommandConsumer(ctx, work[0]); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	work, err = access.PendingCommandConsumers(ctx, 1)
	if err != nil || len(work) != 1 || work[0].Active {
		t.Fatal("foreign organization site move did not queue deletion", err)
	}
	if err = access.CompleteCommandConsumer(ctx, work[0]); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE sites SET tenant_sites=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	work, err = access.PendingCommandConsumers(ctx, 1)
	if err != nil || len(work) != 1 || !work[0].Active {
		t.Fatal("valid restored scope did not queue provisioning", err)
	}
	if err = access.CompleteCommandConsumer(ctx, work[0]); err != nil {
		t.Fatal(err)
	}
	// Set a near-future expiry, then let time pass without any identity update.
	if _, err = s.db.Exec(`UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()+INTERVAL '80 milliseconds' WHERE id=$1`, issued.DeviceID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	work, err = access.PendingCommandConsumers(ctx, 1)
	if err != nil || len(work) != 1 || work[0].Active {
		t.Fatal("elapsed certificate expiry did not queue consumer deletion", err)
	}
}

func TestConcurrentProvisioningPollersLeaseEachDeviceOnce(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	_, token := invite(t, s, Scope{TenantID: 1, SiteID: 1}, 1)
	keys, _ := enrollment.GenerateKeys()
	if _, err := s.Claim(ctx, *proof(t, token, keys)); err != nil {
		t.Fatal(err)
	}
	access, _ := NewAccessStore(s.db)
	var lock sync.Mutex
	count := 0
	var jobs sync.WaitGroup
	for range 8 {
		jobs.Go(func() {
			work, err := access.PendingCommandConsumers(ctx, 1)
			if err != nil {
				t.Error(err)
				return
			}
			lock.Lock()
			count += len(work)
			lock.Unlock()
		})
	}
	jobs.Wait()
	if count != 1 {
		t.Fatal("concurrent pollers duplicated consumer work", count)
	}
}
