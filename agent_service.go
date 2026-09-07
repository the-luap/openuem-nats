package nats

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
)

// AgentAuthorizationService must connect using the isolated auth-service user,
// never an agent or administrator session. Close stops accepting work and waits
// for the bounded in-flight authorizations to observe cancellation.
type AgentAuthorizationService struct {
	subscription *nats.Subscription
	cancel       context.CancelFunc
	mu           sync.Mutex
	closed       bool
	wait         sync.WaitGroup
}

func StartAgentAuthorizationService(ctx context.Context, connection *nats.Conn, authorizer *enrollment.BrokerAuthorizer) (*AgentAuthorizationService, error) {
	if connection == nil || !connection.IsConnected() || authorizer == nil {
		return nil, errors.New("connected isolated broker authorization service required")
	}
	ctx, cancel := context.WithCancel(ctx)
	service := &AgentAuthorizationService{cancel: cancel}
	slots := make(chan struct{}, 32)
	subscription, err := connection.QueueSubscribe(enrollment.AuthorizationSubject, "openuem-agent-authorization", func(message *nats.Msg) {
		service.mu.Lock()
		if service.closed || ctx.Err() != nil {
			service.mu.Unlock()
			_ = message.Respond(nil)
			return
		}
		select {
		case slots <- struct{}{}:
			service.wait.Add(1)
		default:
			service.mu.Unlock()
			_ = message.Respond(nil)
			return
		}
		service.mu.Unlock()
		go func() {
			defer service.wait.Done()
			defer func() { <-slots }()
			response, err := authorizer.Authorize(ctx, message.Data)
			if err != nil {
				_ = message.Respond(nil)
				return
			}
			_ = message.Respond(response)
		}()
	})
	if err != nil {
		cancel()
		return nil, err
	}
	service.subscription = subscription
	if err = subscription.SetPendingLimits(64, 4<<20); err != nil {
		_ = service.Close()
		return nil, err
	}
	if err = connection.FlushTimeout(5 * time.Second); err != nil {
		_ = service.Close()
		return nil, err
	}
	return service, nil
}

func (s *AgentAuthorizationService) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	err := s.subscription.Unsubscribe()
	s.wait.Wait()
	if errors.Is(err, nats.ErrBadSubscription) || errors.Is(err, nats.ErrConnectionClosed) {
		return nil
	}
	return err
}

type BrokerDisconnectStore interface {
	PendingDisconnects(context.Context, int) ([]enrollment.BrokerSession, error)
	CleanExpiredSessions(context.Context) error
}

// DisconnectRevokedSessions uses only the separate private system connection.
// Attempts stay in the database until their lease expires, so a request timeout
// or broker restart never silently consumes the revocation work.
func DisconnectRevokedSessions(ctx context.Context, system *nats.Conn, store BrokerDisconnectStore) error {
	if system == nil || !system.IsConnected() || store == nil {
		return errors.New("connected broker disconnect service required")
	}
	sessions, err := store.PendingDisconnects(ctx, 32)
	if err != nil {
		return err
	}
	results := make(chan error, len(sessions))
	slots := make(chan struct{}, 8)
	var jobs sync.WaitGroup
	defer jobs.Wait()
	for _, session := range sessions {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		jobs.Go(func() {
			defer func() { <-slots }()
			results <- disconnectBrokerSession(ctx, system, session)
		})
	}
	jobs.Wait()
	close(results)
	var result error
	for err := range results {
		if err != nil {
			result = err
		}
	}
	if err = store.CleanExpiredSessions(ctx); err != nil {
		return err
	}
	return result
}

func disconnectBrokerSession(ctx context.Context, system *nats.Conn, session enrollment.BrokerSession) error {
	if !nkeys.IsValidPublicServerKey(session.ServerID) || session.ClientID == 0 {
		return errors.New("invalid persisted broker session")
	}
	body, err := json.Marshal(struct {
		CID uint64 `json:"cid"`
	}{CID: session.ClientID})
	if err != nil {
		return err
	}
	request, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	message, err := system.RequestWithContext(request, "$SYS.REQ.SERVER."+session.ServerID+".KICK", body)
	if err != nil || len(message.Data) > 64<<10 {
		return errors.New("broker disconnect attempt failed")
	}
	var response struct {
		Server struct {
			ID string `json:"id"`
		} `json:"server"`
		Error *struct {
			Code        int    `json:"code"`
			Description string `json:"description"`
		} `json:"error"`
	}
	if err = json.Unmarshal(message.Data, &response); err != nil || response.Server.ID != session.ServerID {
		return errors.New("invalid broker disconnect response")
	}
	if response.Error != nil && !(response.Error.Code == 500 && response.Error.Description == "no such client or leafnode id") {
		return errors.New("broker rejected disconnect request")
	}
	return nil
}
