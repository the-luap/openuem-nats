package nats

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
)

func TestAuthorizationServiceBoundsConcurrentLookupsAndCancelsOnClose(t *testing.T) {
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	defer func() { broker.Shutdown(); broker.WaitForShutdown() }()
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("broker did not start")
	}
	connection, err := nats.Connect(broker.ClientURL(), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	signer, _ := nkeys.CreateAccount()
	issuer, _ := signer.PublicKey()
	device, _ := nkeys.CreateUser()
	devicePublic, _ := device.PublicKey()
	serverKey, _ := nkeys.CreateServer()
	serverID, _ := serverKey.PublicKey()
	oneTime, _ := nkeys.CreateUser()
	oneTimePublic, _ := oneTime.PublicKey()
	request := jwt.NewAuthorizationRequestClaims(issuer)
	request.Audience = "nats-authorization-request"
	request.UserNkey = oneTimePublic
	request.Server.ID = serverID
	request.ClientInformation.ID = 42
	request.ClientInformation.Nonce = "testnonce123456"
	request.ConnectOptions.Nkey = devicePublic
	signature, _ := device.Sign([]byte(request.ClientInformation.Nonce))
	request.ConnectOptions.SignedNonce = base64.RawURLEncoding.EncodeToString(signature)
	request.Expires = time.Now().Add(10 * time.Second).Unix()
	encoded, err := request.Encode(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	var active, maximum atomic.Int32
	saturated := make(chan struct{})
	var saturatedOnce sync.Once
	authorizer, err := enrollment.NewBrokerAuthorizer(signer, "UEM_DEVICES", func(ctx context.Context, _ string, _ enrollment.BrokerSession) (*enrollment.BrokerIdentity, error) {
		count := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); count > old; old = maximum.Load() {
			if maximum.CompareAndSwap(old, count) {
				break
			}
		}
		if count == 32 {
			saturatedOnce.Do(func() { close(saturated) })
		}
		<-ctx.Done()
		return nil, errors.New("lookup canceled")
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := StartAgentAuthorizationService(context.Background(), connection, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	for range 64 {
		if err = connection.PublishRequest(enrollment.AuthorizationSubject, "_INBOX.test", []byte(encoded)); err != nil {
			t.Fatal(err)
		}
	}
	if err = connection.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case <-saturated:
	case <-time.After(2 * time.Second):
		t.Fatal("lookups did not reach bounded concurrency")
	}
	start := time.Now()
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	if active.Load() != 0 || maximum.Load() > 32 || time.Since(start) > 2*time.Second {
		t.Fatal("service shutdown leaked or overran lookups")
	}
}
