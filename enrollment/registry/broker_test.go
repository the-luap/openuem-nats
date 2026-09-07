package registry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
)

func TestDurableEnrollmentAuthorizesRealBrokerAndRevocationDisconnectsIt(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	_, token := invite(t, store, Scope{TenantID: 1, SiteID: 1}, 1)
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Claim(ctx, *proof(t, token, keys))
	if err != nil {
		t.Fatal(err)
	}
	access, _ := NewAccessStore(store.db)
	signer, _ := nkeys.CreateAccount()
	issuer, _ := signer.PublicKey()
	authKey, _ := nkeys.CreateUser()
	authPublic, _ := authKey.PublicKey()
	systemKey, _ := nkeys.CreateUser()
	systemPublic, _ := systemKey.PublicKey()
	authAccount, deviceAccount, systemAccount := server.NewAccount("UEM_AUTH"), server.NewAccount("UEM_DEVICES"), server.NewAccount("UEM_SYSTEM")
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certServer.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	certServer.Close()
	broker, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
		Websocket: server.WebsocketOpts{Host: "127.0.0.1", Port: -1, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}},
		Accounts:  []*server.Account{authAccount, deviceAccount, systemAccount}, SystemAccount: "UEM_SYSTEM",
		Nkeys: []*server.NkeyUser{
			{Nkey: authPublic, Account: authAccount, Permissions: &server.Permissions{Publish: &server.SubjectPermission{Deny: []string{">"}}, Subscribe: &server.SubjectPermission{Allow: []string{enrollment.AuthorizationSubject}}, Response: &server.ResponsePermission{MaxMsgs: 1, Expires: time.Second}}},
			{Nkey: systemPublic, Account: systemAccount, Permissions: &server.Permissions{Publish: &server.SubjectPermission{Allow: []string{"$SYS.REQ.SERVER.*.KICK"}}, Subscribe: &server.SubjectPermission{Allow: []string{"_INBOX.>"}}}},
		},
		AuthCallout: &server.AuthCallout{Issuer: issuer, Account: "UEM_AUTH", AuthUsers: []string{authPublic}, AllowedAccounts: []string{"UEM_DEVICES"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("broker did not start")
	}
	auth, err := nats.Connect(broker.ClientURL(), nats.Nkey(authPublic, authKey.Sign), nats.Secure(&tls.Config{RootCAs: roots}), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()
	authorizer, err := enrollment.NewBrokerAuthorizer(signer, "UEM_DEVICES", access.AuthorizeDevice)
	if err != nil {
		t.Fatal(err)
	}
	_, err = auth.Subscribe(enrollment.AuthorizationSubject, func(message *nats.Msg) {
		response, err := authorizer.Authorize(ctx, message.Data)
		if err != nil {
			_ = message.Respond(nil)
			return
		}
		_ = message.Respond(response)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = auth.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	public, _ := keys.Broker.PublicKey()
	prefix, _ := enrollment.ReplyPrefix(issued.DeviceID)
	closed := make(chan struct{}, 1)
	endpoint := broker.WebsocketURL() + "/agent-channel"
	options := []nats.Option{nats.Nkey(public, keys.Broker.Sign), nats.CustomInboxPrefix(prefix), nats.Secure(&tls.Config{RootCAs: roots}), nats.NoReconnect()}
	client, err := nats.Connect(endpoint, append(options, nats.ClosedHandler(func(*nats.Conn) { closed <- struct{}{} }))...)
	if err != nil {
		t.Fatal("durably enrolled key was rejected", err)
	}
	defer client.Close()
	var sessions int
	if err = store.db.QueryRow(`SELECT count(*) FROM uem_agent_broker_sessions WHERE device_id=$1`, issued.DeviceID).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatal("actual broker connection was not recorded", err)
	}
	if err = store.RevokeIdentity(ctx, Scope{TenantID: 1}, issued.DeviceID, "test-admin"); err != nil {
		t.Fatal(err)
	}
	// Recreate the access component to prove the disconnect outbox is durable.
	restarted, _ := NewAccessStore(store.db)
	batch, err := restarted.PendingDisconnects(ctx, 10)
	if err != nil || len(batch) != 1 {
		t.Fatal("revocation lost broker session", err)
	}
	system, err := nats.Connect(broker.ClientURL(), nats.Nkey(systemPublic, systemKey.Sign), nats.Secure(&tls.Config{RootCAs: roots}), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer system.Close()
	for _, session := range batch {
		if session.ServerID != broker.ID() {
			t.Fatal("wrong server persisted")
		}
		body, _ := json.Marshal(server.KickClientReq{CID: session.ClientID})
		if _, err = system.Request("$SYS.REQ.SERVER."+session.ServerID+".KICK", body, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("persisted revocation did not disconnect client")
	}
	if retry, err := nats.Connect(endpoint, options...); err == nil {
		retry.Close()
		t.Fatal("revoked key authenticated after restart")
	}
}
