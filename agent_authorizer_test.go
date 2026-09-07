package nats

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
)

func TestBrokerCalloutRejectsUnknownRevokedKeysAndDisconnectsExistingSessions(t *testing.T) {
	const deviceID = "12345678-1234-4234-8234-123456789abc"
	signer, _ := nkeys.CreateAccount()
	issuer, _ := signer.PublicKey()
	authKey, _ := nkeys.CreateUser()
	authPublic, _ := authKey.PublicKey()
	deviceKey, _ := nkeys.CreateUser()
	devicePublic, _ := deviceKey.PublicKey()
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateServer.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certificateServer.Certificate())
	certificateServer.Close()
	authAccount := server.NewAccount("UEM_AUTH")
	deviceAccount := server.NewAccount("UEM_DEVICES")
	systemAccount := server.NewAccount("UEM_SYSTEM")
	s, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
		Websocket: server.WebsocketOpts{Host: "127.0.0.1", Port: -1, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}},
		Accounts:  []*server.Account{authAccount, deviceAccount, systemAccount}, SystemAccount: "UEM_SYSTEM",
		// A configured service NKey enables nonce challenges in the stock broker.
		// Auth callout alone does not enable them; AlwaysEnableNonce is embed-only.
		Nkeys: []*server.NkeyUser{{Nkey: authPublic, Account: authAccount, Permissions: &server.Permissions{
			Publish:   &server.SubjectPermission{Deny: []string{">"}},
			Subscribe: &server.SubjectPermission{Allow: []string{enrollment.AuthorizationSubject}},
			Response:  &server.ResponsePermission{MaxMsgs: 1, Expires: time.Second},
		}}},
		Users:       []*server.User{{Username: "system-service", Password: "isolated-system-test-only", Account: systemAccount}},
		AuthCallout: &server.AuthCallout{Issuer: issuer, Account: "UEM_AUTH", AuthUsers: []string{authPublic}, AllowedAccounts: []string{"UEM_DEVICES"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	defer func() { s.Shutdown(); s.WaitForShutdown() }()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("broker did not start")
	}
	auth, err := nats.Connect(s.ClientURL(), nats.Nkey(authPublic, authKey.Sign), nats.Secure(&tls.Config{RootCAs: roots}))
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()
	var revoked atomic.Bool
	var certificateExpiry atomic.Int64
	certificateExpiry.Store(time.Now().Add(time.Hour).Unix())
	sessions := make(chan enrollment.BrokerSession, 8)
	authorizer, err := enrollment.NewBrokerAuthorizer(signer, "UEM_DEVICES", func(ctx context.Context, key string, session enrollment.BrokerSession) (*enrollment.BrokerIdentity, error) {
		if key != devicePublic || revoked.Load() {
			return nil, errors.New("not active")
		}
		sessions <- session
		return &enrollment.BrokerIdentity{DeviceID: deviceID, CertificateExpiresAt: time.Unix(certificateExpiry.Load(), 0)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := StartAgentAuthorizationService(context.Background(), auth, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	disconnected := make(chan struct{}, 8)
	config := AgentConnection{Endpoint: s.WebsocketURL() + "/agent-channel", DeviceID: deviceID, BrokerKey: deviceKey, Roots: roots, Event: func(state string) {
		if state == "disconnected" {
			disconnected <- struct{}{}
		}
	}}
	client, err := ConnectAgent(config)
	if err != nil {
		t.Fatal("callout rejected a valid individual key", err)
	}
	defer client.Close()
	var session enrollment.BrokerSession
	select {
	case session = <-sessions:
	case <-time.After(time.Second):
		t.Fatal("active session was not recorded")
	}
	if session.ServerID != s.ID() || session.ClientID == 0 {
		t.Fatal("recorded session does not identify the actual broker/client")
	}
	unknown, _ := nkeys.CreateUser()
	other := config
	other.BrokerKey = unknown
	other.Event = nil
	if c, err := ConnectAgent(other); err == nil {
		c.Close()
		t.Fatal("unregistered device key authenticated through callout")
	}
	revoked.Store(true)
	system, err := nats.Connect(s.ClientURL(), nats.UserInfo("system-service", "isolated-system-test-only"), nats.Secure(&tls.Config{RootCAs: roots}))
	if err != nil {
		t.Fatal(err)
	}
	defer system.Close()
	disconnectStore := &testDisconnectStore{sessions: []enrollment.BrokerSession{session}}
	if err = DisconnectRevokedSessions(context.Background(), system, disconnectStore); err != nil || !disconnectStore.cleaned {
		t.Fatal("revoked session disconnect failed", err)
	}
	select {
	case <-disconnected:
	case <-time.After(2 * time.Second):
		t.Fatal("revoked connection remained open")
	}
	config.Event = nil
	if c, err := ConnectAgent(config); err == nil {
		c.Close()
		t.Fatal("revoked key reconnected")
	}
	client.Close()
	revoked.Store(false)
	certificateExpiry.Store(time.Now().Add(2 * time.Second).Unix())
	expired := make(chan struct{}, 8)
	config.Event = func(state string) {
		if state == "disconnected" {
			expired <- struct{}{}
		}
	}
	shortLived, err := ConnectAgent(config)
	if err != nil {
		t.Fatal("short-lived valid enrollment rejected", err)
	}
	defer shortLived.Close()
	select {
	case <-expired:
	case <-time.After(3 * time.Second):
		t.Fatal("broker did not disconnect expired enrollment")
	}
	shortLived.Close()
	config.Event = nil
	if c, err := ConnectAgent(config); err == nil {
		c.Close()
		t.Fatal("expired enrollment reconnected")
	}
	certificateExpiry.Store(time.Now().Add(time.Hour).Unix())
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	if c, err := ConnectAgent(config); err == nil {
		c.Close()
		t.Fatal("authorization outage admitted device")
	}
}

// A read-only fixture retains disconnect work like the durable registry outbox.
type testDisconnectStore struct {
	sessions []enrollment.BrokerSession
	cleaned  bool
}

func (s *testDisconnectStore) PendingDisconnects(context.Context, int) ([]enrollment.BrokerSession, error) {
	return append([]enrollment.BrokerSession(nil), s.sessions...), nil
}
func (s *testDisconnectStore) CleanExpiredSessions(context.Context) error {
	s.cleaned = true
	return nil
}
