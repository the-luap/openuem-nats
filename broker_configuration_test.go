package nats

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
)

func TestGeneratedBrokerConfigSeparatesServicesAndFixedDeviceConsumers(t *testing.T) {
	directory := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test broker CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(directory, "ca.pem")
	if err = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0644); err != nil {
		t.Fatal(err)
	}
	makeCertificate := func(serial int64, usage x509.ExtKeyUsage) (tls.Certificate, string, string) {
		t.Helper()
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Test TLS identity"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certificate, private := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		pair, err := tls.X509KeyPair(certificate, private)
		if err != nil {
			t.Fatal(err)
		}
		certPath, keyPath := filepath.Join(t.TempDir(), "tls.pem"), filepath.Join(t.TempDir(), "tls.key")
		if err = os.WriteFile(certPath, certificate, 0644); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(keyPath, private, 0600); err != nil {
			t.Fatal(err)
		}
		return pair, certPath, keyPath
	}
	_, certificatePath, keyPath := makeCertificate(2, x509.ExtKeyUsageServerAuth)
	gatewayCertificate, _, _ := makeCertificate(3, x509.ExtKeyUsageClientAuth)
	signer, _ := nkeys.CreateAccount()
	issuer, _ := signer.PublicKey()
	users, public := make([]nkeys.KeyPair, 5), make([]string, 5)
	for i := range users {
		users[i], _ = nkeys.CreateUser()
		public[i], _ = users[i].PublicKey()
	}
	freeAddress := func() string {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		listener.Close()
		return address
	}
	config := enrollment.BrokerConfiguration{Name: "individual-test", Listen: freeAddress(), WebsocketListen: freeAddress(), CertificateFile: certificatePath, KeyFile: keyPath, GatewayCAFile: caPath, StoreDirectory: filepath.Join(directory, "jetstream"), Issuer: issuer, AuthorizationUser: public[0], RevocationUser: public[1], WorkerUser: public[2], ConsoleUser: public[3], ProvisionerUser: public[4]}
	encoded, err := config.Render()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "PRIVATE KEY") {
		t.Fatal("configuration contains a private key")
	}
	configPath := filepath.Join(directory, "broker.json")
	if err = os.WriteFile(configPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	options, err := server.ProcessConfigFile(configPath)
	if err != nil {
		t.Fatal("generated configuration rejected by stock NATS parser", err)
	}
	options.NoLog, options.NoSigs = true, true
	broker, err := server.NewServer(options)
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("configured broker did not start")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	permissionErrors := make([]chan error, len(users))
	connections := make([]*nats.Conn, len(users))
	for i, key := range users {
		permissionErrors[i] = make(chan error, 16)
		connections[i], err = nats.Connect(broker.ClientURL(), nats.Secure(&tls.Config{RootCAs: roots}), nats.Nkey(public[i], key.Sign), nats.NoReconnect(), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { permissionErrors[i] <- err }))
		if err != nil {
			t.Fatalf("configured service %d did not authenticate independently: %v", i, err)
		}
		defer connections[i].Close()
	}
	wrongProof, _ := nkeys.CreateUser()
	if connection, err := nats.Connect(broker.ClientURL(), nats.Secure(&tls.Config{RootCAs: roots}), nats.Nkey(public[2], wrongProof.Sign), nats.NoReconnect()); err == nil {
		connection.Close()
		t.Fatal("static service bypass accepted a public key without its nonce proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	deviceKey, _ := nkeys.CreateUser()
	devicePublic, _ := deviceKey.PublicKey()
	id, foreignID := "12345678-1234-4234-8234-123456789abc", "12345678-1234-4234-8234-123456789abd"
	authorizer, err := enrollment.NewBrokerAuthorizer(signer, "UEM_DEVICES", func(_ context.Context, public string, _ enrollment.BrokerSession) (*enrollment.BrokerIdentity, error) {
		if public != devicePublic {
			return nil, errors.New("unknown device")
		}
		return &enrollment.BrokerIdentity{DeviceID: id, CertificateExpiresAt: time.Now().Add(time.Hour)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	authService, err := StartAgentAuthorizationService(ctx, connections[0], authorizer)
	if err != nil {
		t.Fatal(err)
	}
	defer authService.Close()
	js, err := jetstream.New(connections[4])
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = EnsureAgentCommandStream(ctx, js); err != nil {
			t.Fatal("fixed stream provisioning failed", err)
		}
		if err = EnsureAgentCommandConsumer(ctx, js, id); err != nil {
			t.Fatal("fixed consumer provisioning failed", err)
		}
	}
	if err = EnsureAgentCommandConsumer(ctx, js, foreignID); err != nil {
		t.Fatal(err)
	}
	// WSS is a private gateway backend; even a valid device key cannot connect
	// directly without the gateway's distinct TLS certificate.
	endpoint := broker.WebsocketURL() + "/agent-channel"
	if client, err := ConnectAgent(AgentConnection{Endpoint: endpoint, DeviceID: id, BrokerKey: deviceKey, Roots: roots}); err == nil {
		client.Close()
		t.Fatal("private WSS accepted a direct device connection")
	}
	deviceErrors := make(chan error, 16)
	device, err := ConnectAgent(AgentConnection{Endpoint: endpoint, DeviceID: id, BrokerKey: deviceKey, Roots: roots, Certificate: &gatewayCertificate, ErrorHandler: func(_ *nats.Conn, _ *nats.Subscription, err error) { deviceErrors <- err }})
	if err != nil {
		t.Fatal("gateway TLS and individual nonce proof were rejected", err)
	}
	defer device.Close()
	subject, _ := enrollment.RequestSubject(id, "report")
	_, err = connections[2].QueueSubscribe("uem.v1.agent.*.request.report", "openuem-individual-agents", func(message *nats.Msg) {
		if enrollment.ValidReply(id, message.Reply) {
			_ = message.Respond([]byte("accepted"))
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = connections[2].FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	response, err := device.Request(subject, []byte(`{}`), time.Second)
	if err != nil || string(response.Data) != "accepted" {
		t.Fatal("configured worker could not reply to individual device", err)
	}
	consoleJS, _ := jetstream.New(connections[3])
	for _, target := range []string{foreignID, id} {
		if _, err = consoleJS.Publish(ctx, "agent.report."+target, []byte(target)); err != nil {
			t.Fatal("console command publication failed", err)
		}
	}
	deviceJS, _ := jetstream.New(device)
	consumerName, _ := enrollment.ConsumerName(id)
	consumer, err := OpenAgentCommandConsumer(ctx, deviceJS, id)
	if err != nil {
		t.Fatal(err)
	}
	message, err := consumer.Next(jetstream.FetchMaxWait(time.Second))
	if err != nil || string(message.Data()) != id {
		t.Fatal("device did not receive only its own queued command", err)
	}
	if err = message.DoubleAck(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = consumer.Next(jetstream.FetchMaxWait(100 * time.Millisecond)); err == nil {
		t.Fatal("device consumed foreign queued command")
	}
	denied := func(connection *nats.Conn, errors <-chan error, subject string, subscribe bool) {
		t.Helper()
		if subscribe {
			_, err = connection.Subscribe(subject, func(*nats.Msg) {})
		} else {
			err = connection.Publish(subject, []byte(`{}`))
		}
		if err != nil {
			t.Fatal(err)
		}
		if err = connection.FlushTimeout(time.Second); err != nil {
			t.Fatal(err)
		}
		select {
		case <-errors:
		case <-time.After(2 * time.Second):
			t.Fatal("forbidden broker operation was allowed", subject)
		}
	}
	denied(device, deviceErrors, "$JS.API.CONSUMER.CREATE.AGENTS_STREAM.Attacker", false)
	denied(device, deviceErrors, enrollment.AuthorizationSubject, true)
	denied(connections[2], permissionErrors[2], "agent.report."+id, false)
	denied(connections[3], permissionErrors[3], "$JS.API.CONSUMER.CREATE.AGENTS_STREAM.Attacker", false)
	denied(connections[4], permissionErrors[4], "agent.report."+id, false)
	denied(connections[1], permissionErrors[1], "$SYS.REQ.SERVER."+broker.ID()+".SHUTDOWN", false)
	// Existing conflicting consumer definitions must fail closed, preserving the
	// actual definition instead of widening or silently taking it over.
	info, err := consumer.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conflicting := info.Config
	conflicting.FilterSubjects = []string{"agent.report." + id}
	if _, err = js.UpdateConsumer(ctx, "AGENTS_STREAM", conflicting); err != nil {
		t.Fatal(err)
	}
	if err = EnsureAgentCommandConsumer(ctx, js, id); !errors.Is(err, ErrAgentCommands) {
		t.Fatal("unexpected consumer configuration silently accepted", err)
	}
	if _, err = OpenAgentCommandConsumer(ctx, deviceJS, id); !errors.Is(err, ErrAgentCommands) {
		t.Fatal("endpoint accepted a conflicting fixed consumer", err)
	}
	info, err = consumer.Info(ctx)
	if err != nil || len(info.Config.FilterSubjects) != 1 || info.Config.FilterSubjects[0] != "agent.report."+id {
		t.Fatal("endpoint rewrote the conflicting consumer", err)
	}
	if err = js.DeleteConsumer(ctx, "AGENTS_STREAM", consumerName); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenAgentCommandConsumer(ctx, deviceJS, id); !errors.Is(err, ErrAgentCommands) {
		t.Fatal("endpoint recreated its missing consumer", err)
	}
	if _, err = js.Consumer(ctx, "AGENTS_STREAM", consumerName); !errors.Is(err, jetstream.ErrConsumerNotFound) {
		t.Fatal("read-only consumer opening created broker state", err)
	}
	if err = EnsureAgentCommandConsumer(ctx, js, id); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenAgentCommandConsumer(ctx, deviceJS, id); err != nil {
		t.Fatal("endpoint could not retry after server reconciliation", err)
	}
}
