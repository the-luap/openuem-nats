package nats

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/open-uem/nats/enrollment"
)

type CommandConsumerStore interface {
	PendingCommandConsumers(context.Context, int) ([]enrollment.CommandConsumerWork, error)
	CompleteCommandConsumer(context.Context, enrollment.CommandConsumerWork) error
}

// ReconcileAgentCommandConsumers requires a separate trusted provisioning NKey.
// Uncertain operations retain their durable lease for retry; a periodic check
// also recovers a crash between a successful broker change and its acknowledgment.
func ReconcileAgentCommandConsumers(ctx context.Context, js jetstream.JetStream, store CommandConsumerStore) error {
	if js == nil || store == nil {
		return ErrAgentCommands
	}
	setup, cancel := context.WithTimeout(ctx, 3*time.Second)
	err := EnsureAgentCommandStream(setup, js)
	cancel()
	if err != nil {
		return err
	}
	work, err := store.PendingCommandConsumers(ctx, 32)
	if err != nil {
		return err
	}
	errorsFound := make(chan error, len(work))
	slots := make(chan struct{}, 8)
	var jobs sync.WaitGroup
	defer jobs.Wait()
	for _, item := range work {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		jobs.Go(func() {
			defer func() { <-slots }()
			attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			if !enrollment.ValidDeviceID(item.DeviceID) || item.Revision < 1 || !enrollment.ValidDeviceID(item.LeaseID) {
				errorsFound <- ErrAgentCommands
				return
			}
			var err error
			if item.Active {
				err = EnsureAgentCommandConsumer(attempt, js, item.DeviceID)
			} else {
				name, _ := enrollment.ConsumerName(item.DeviceID)
				err = js.DeleteConsumer(attempt, "AGENTS_STREAM", name)
				if errors.Is(err, jetstream.ErrConsumerNotFound) {
					err = nil
				}
			}
			if err == nil {
				err = store.CompleteCommandConsumer(attempt, item)
			}
			if err != nil {
				errorsFound <- ErrAgentCommands
			}
		})
	}
	jobs.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			return err
		}
	}
	return nil
}
