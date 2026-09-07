package nats

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
)

func TestIndividualAgentWSSIdentityAndSubjectIsolation(t *testing.T) {
	id := "12345678-1234-4234-8234-123456789abc"
	foreign := "12345678-1234-4234-8234-123456789abd"
	keys, _ := nkeys.CreateUser()
	public, _ := keys.PublicKey()
	workerKey, _ := nkeys.CreateUser()
	workerPublic, _ := workerKey.PublicKey()
	policy, err := enrollment.DeviceSubjects(id)
	if err != nil {
		t.Fatal(err)
	}
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certServer.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	certServer.Close()
	s, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true, JetStream: true, StoreDir: t.TempDir(),
		Websocket: server.WebsocketOpts{Host: "127.0.0.1", Port: -1, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}},
		Nkeys: []*server.NkeyUser{
			{Nkey: public, Permissions: &server.Permissions{Publish: &server.SubjectPermission{Allow: policy.Publish}, Subscribe: &server.SubjectPermission{Allow: policy.Subscribe}, Response: &server.ResponsePermission{MaxMsgs: policy.ReplyMaxMessages, Expires: time.Duration(policy.ReplyMaxSeconds) * time.Second}}},
			{Nkey: workerPublic},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	t.Cleanup(func() { s.Shutdown(); s.WaitForShutdown() })
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS test broker did not start")
	}
	endpoint := s.WebsocketURL() + "/agent-channel"
	worker, err := nats.Connect(endpoint, nats.Secure(&tls.Config{RootCAs: roots}), nats.Nkey(workerPublic, workerKey.Sign))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	permissionErrors := make(chan error, 16)
	client, err := ConnectAgent(AgentConnection{Endpoint: endpoint, DeviceID: id, BrokerKey: keys, Roots: roots, ErrorHandler: func(_ *nats.Conn, _ *nats.Subscription, err error) { permissionErrors <- err }})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	denied := func(action func() error) {
		t.Helper()
		if err := action(); err != nil {
			t.Fatal("request did not reach permission check", err)
		}
		if err := client.FlushTimeout(time.Second); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-permissionErrors:
			if !strings.Contains(strings.ToLower(err.Error()), "permissions") {
				t.Fatal("unexpected broker error", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("broker did not deny another device or privileged subject")
		}
	}
	for _, subject := range []string{"agent.reboot." + foreign, "_INBOX.>", "uem.v1.agent." + foreign + ".reply.>", "$SYS.REQ.USER.AUTH", "agent.newconfig"} {
		denied(func() error { _, err := client.Subscribe(subject, func(*nats.Msg) {}); return err })
	}
	for _, subject := range []string{"report", "agent.reboot." + foreign, "uem.v1.agent." + foreign + ".request.report", "$JS.API.CONSUMER.CREATE.AGENTS_STREAM.AgentConsumer" + id, "$JS.API.CONSUMER.MSG.NEXT.AGENTS_STREAM.AgentConsumer" + foreign, "_INBOX.administrator"} {
		denied(func() error { return client.Publish(subject, []byte("forged")) })
	}
	requestSubject, _ := enrollment.RequestSubject(id, "report")
	_, err = worker.Subscribe(requestSubject, func(msg *nats.Msg) {
		if !enrollment.ValidReply(id, msg.Reply) {
			return
		}
		_ = msg.Respond([]byte("accepted"))
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = worker.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	response, err := client.Request(requestSubject, []byte("report"), time.Second)
	if err != nil || string(response.Data) != "accepted" {
		t.Fatal("private inbox request failed", err)
	}
	foreignCommands, err := worker.SubscribeSync("agent.reboot." + foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err = worker.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if err = client.PublishRequest(requestSubject, "agent.reboot."+foreign, []byte("forged reply")); err != nil {
		t.Fatal(err)
	}
	if err = client.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = foreignCommands.NextMsg(100 * time.Millisecond); err != nats.ErrTimeout {
		t.Fatal("worker reply became a foreign command", err)
	}
	// A real inbound command permits one response to its caller, without a
	// blanket publish permission on the caller's inbox.
	_, err = client.Subscribe("agent.ping."+id, func(msg *nats.Msg) { _ = msg.Respond([]byte("pong")) })
	if err != nil {
		t.Fatal(err)
	}
	if err = client.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	response, err = worker.Request("agent.ping."+id, nil, time.Second)
	if err != nil || string(response.Data) != "pong" {
		t.Fatal("temporary reply permission failed", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	adminJS, err := jetstream.New(worker)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adminJS.CreateStream(ctx, jetstream.StreamConfig{Name: "AGENTS_STREAM", Subjects: []string{"agent.report.*"}, Storage: jetstream.MemoryStorage})
	if err != nil {
		t.Fatal(err)
	}
	consumerName, _ := enrollment.ConsumerName(id)
	_, err = adminJS.CreateConsumer(ctx, "AGENTS_STREAM", jetstream.ConsumerConfig{Durable: consumerName, FilterSubject: "agent.report." + id, AckPolicy: jetstream.AckExplicitPolicy})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = adminJS.Publish(ctx, "agent.report."+foreign, []byte("foreign")); err != nil {
		t.Fatal(err)
	}
	if _, err = adminJS.Publish(ctx, "agent.report."+id, []byte("own")); err != nil {
		t.Fatal(err)
	}
	agentJS, err := jetstream.New(client)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := agentJS.Consumer(ctx, "AGENTS_STREAM", consumerName)
	if err != nil {
		t.Fatal("agent could not open its pre-provisioned consumer", err)
	}
	message, err := consumer.Next(jetstream.FetchMaxWait(time.Second))
	if err != nil || string(message.Data()) != "own" {
		t.Fatal("consumer did not isolate device delivery", err)
	}
	if err = message.DoubleAck(ctx); err != nil {
		t.Fatal("device could not acknowledge its own message", err)
	}
	unknown, _ := nkeys.CreateUser()
	if nc, err := ConnectAgent(AgentConnection{Endpoint: endpoint, DeviceID: id, BrokerKey: unknown, Roots: roots}); err == nil {
		nc.Close()
		t.Fatal("unregistered broker key authenticated")
	}
	if nc, err := ConnectAgent(AgentConnection{Endpoint: endpoint, DeviceID: id, BrokerKey: keys}); err == nil {
		nc.Close()
		t.Fatal("untrusted gateway certificate accepted")
	}
}

func TestAgentEndpointRejectsInsecureOrCredentialBearingURLs(t *testing.T) {
	keys, _ := nkeys.CreateUser()
	for _, endpoint := range []string{"ws://example.com/agent-channel", "nats://example.com:4222", "wss://user:secret@example.com/agent-channel", "wss://example.com/agent-channel?token=secret", "wss://example.com/agent-channel#secret", "wss://example.com/admin", "wss://example.com/agent%2Dchannel", "wss://example.com/agent-channel?"} {
		config := AgentConnection{Endpoint: endpoint, DeviceID: "12345678-1234-4234-8234-123456789abc", BrokerKey: keys}
		if _, err := config.options(); err == nil {
			t.Fatal("unsafe agent endpoint accepted", endpoint)
		}
	}
}
