package nats

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/open-uem/nats/enrollment"
)

var ErrAgentCommands = errors.New("individual agent command provisioning failed or conflicts with existing configuration")

var durableAgentOperations = []string{"enable", "disable", "report", "update.updater", "rollback.updater", "uninstall"}

func commandSubjects(id string) []string {
	subjects := make([]string, 0, len(durableAgentOperations))
	for _, operation := range durableAgentOperations {
		subjects = append(subjects, "agent."+operation+"."+id)
	}
	return subjects
}

func sameSubjects(left, right []string) bool {
	left, right = slices.Clone(left), slices.Clone(right)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

// EnsureAgentCommandStream is called by the trusted provisioning service, never
// by an endpoint or normal worker. Existing incompatible streams are not rewritten.
func EnsureAgentCommandStream(ctx context.Context, js jetstream.JetStream) error {
	if js == nil {
		return ErrAgentCommands
	}
	expected := jetstream.StreamConfig{
		Name: "AGENTS_STREAM", Subjects: commandSubjects("*"), Storage: jetstream.FileStorage,
		Retention: jetstream.WorkQueuePolicy, Discard: jetstream.DiscardNew, DiscardNewPerSubject: true,
		MaxAge: 7 * 24 * time.Hour, MaxBytes: int64(5) << 30, MaxMsgSize: 64 << 10,
		MaxMsgsPerSubject: 64, Replicas: 1, DenyDelete: true, DenyPurge: true,
	}
	stream, err := js.CreateStream(ctx, expected)
	if err != nil {
		stream, err = js.Stream(ctx, expected.Name)
		if err != nil {
			return ErrAgentCommands
		}
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return ErrAgentCommands
	}
	actual := info.Config
	if !sameSubjects(actual.Subjects, expected.Subjects) || actual.Storage != expected.Storage || actual.Retention != expected.Retention || actual.Discard != expected.Discard || !actual.DiscardNewPerSubject || actual.MaxAge != expected.MaxAge || actual.MaxBytes != expected.MaxBytes || actual.MaxMsgSize != expected.MaxMsgSize || actual.MaxMsgsPerSubject != expected.MaxMsgsPerSubject || actual.Replicas != expected.Replicas || !actual.DenyDelete || !actual.DenyPurge || actual.Mirror != nil || len(actual.Sources) != 0 || actual.SubjectTransform != nil || actual.RePublish != nil || actual.Sealed || actual.NoAck {
		return ErrAgentCommands
	}
	return nil
}

// EnsureAgentCommandConsumer binds a durable pull consumer to a single device.
// Certificates/private keys are deliberately absent from the durable subjects.
func EnsureAgentCommandConsumer(ctx context.Context, js jetstream.JetStream, deviceID string) error {
	name, err := enrollment.ConsumerName(deviceID)
	if err != nil || js == nil {
		return ErrAgentCommands
	}
	expected := agentCommandConsumerConfig(name, deviceID)
	consumer, err := js.CreateConsumer(ctx, "AGENTS_STREAM", expected)
	if err != nil {
		consumer, err = js.Consumer(ctx, "AGENTS_STREAM", name)
		if err != nil {
			return ErrAgentCommands
		}
	}
	info, err := consumer.Info(ctx)
	if err != nil || !validAgentCommandConsumer(info, name, expected) {
		return ErrAgentCommands
	}
	return nil
}

// OpenAgentCommandConsumer only reads the endpoint's fixed consumer. It never
// creates/updates a stream or consumer, including when provisioning is delayed
// or an existing definition is incompatible. Callers retry after reconciliation.
func OpenAgentCommandConsumer(ctx context.Context, js jetstream.JetStream, deviceID string) (jetstream.Consumer, error) {
	name, err := enrollment.ConsumerName(deviceID)
	if err != nil || js == nil {
		return nil, ErrAgentCommands
	}
	consumer, err := js.Consumer(ctx, "AGENTS_STREAM", name)
	if err != nil {
		return nil, ErrAgentCommands
	}
	// Consumer() already performs an INFO request; validate that response without
	// an unnecessary second round trip or a broader stream-management request.
	if !validAgentCommandConsumer(consumer.CachedInfo(), name, agentCommandConsumerConfig(name, deviceID)) {
		return nil, ErrAgentCommands
	}
	return consumer, nil
}

func agentCommandConsumerConfig(name, deviceID string) jetstream.ConsumerConfig {
	return jetstream.ConsumerConfig{
		Name: name, Durable: name, FilterSubjects: commandSubjects(deviceID),
		AckPolicy: jetstream.AckExplicitPolicy, AckWait: 5 * time.Minute, MaxDeliver: 5,
		MaxAckPending: 1, DeliverPolicy: jetstream.DeliverAllPolicy, ReplayPolicy: jetstream.ReplayInstantPolicy,
		MaxRequestBatch: 1, MaxRequestExpires: 30 * time.Second, MaxWaiting: 16,
	}
}

func validAgentCommandConsumer(info *jetstream.ConsumerInfo, name string, expected jetstream.ConsumerConfig) bool {
	if info == nil || info.Name != name || info.Stream != "AGENTS_STREAM" {
		return false
	}
	actual := info.Config
	return actual.Name == name && actual.Durable == name && actual.FilterSubject == "" && sameSubjects(actual.FilterSubjects, expected.FilterSubjects) && actual.AckPolicy == expected.AckPolicy && actual.AckWait == expected.AckWait && actual.MaxDeliver == expected.MaxDeliver && actual.MaxAckPending == 1 && actual.DeliverPolicy == expected.DeliverPolicy && actual.ReplayPolicy == expected.ReplayPolicy && actual.MaxRequestBatch == 1 && actual.MaxRequestExpires == expected.MaxRequestExpires && actual.MaxWaiting == expected.MaxWaiting && len(actual.BackOff) == 0 && !actual.HeadersOnly && actual.InactiveThreshold == 0 && actual.PauseUntil == nil
}
