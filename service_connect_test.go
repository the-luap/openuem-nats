package nats

import (
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
)

func TestServiceConnectionRequiresExplicitTLSOrigins(t *testing.T) {
	for _, address := range []string{"", "nats://localhost:4222", "wss://localhost:443", "tls://user:secret@localhost", "tls://localhost/", "tls://localhost?", "tls://localhost#fragment", "tls://localhost,", "tls://localhost, nats://other"} {
		if ValidServiceURLs(address) {
			t.Fatalf("accepted unsafe service origin %q", address)
		}
	}
	if !ValidServiceURLs("tls://broker.internal:4222,tls://[::1]:4222") {
		t.Fatal("valid service origins rejected")
	}
}

func TestServiceConnectionUsesProtectedNKeyAndVerifiedTLSAfterRestart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("TLS integration runs on Unix; keyfile ACLs have native Windows tests")
	}
	key, _ := nkeys.CreateUser()
	public, _ := key.PublicKey()
	seed, _ := key.Seed()
	keyPath := filepath.Join(t.TempDir(), "worker.seed")
	if err := os.WriteFile(keyPath, seed, 0600); err != nil {
		t.Fatal(err)
	}
	clear(seed)
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certServer.TLS.Certificates[0]
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certServer.Certificate().Raw}), 0644); err != nil {
		t.Fatal(err)
	}
	certServer.Close()
	options := &server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
		Nkeys:     []*server.NkeyUser{{Nkey: public}},
	}
	start := func() *server.Server {
		t.Helper()
		broker, err := server.NewServer(options)
		if err != nil {
			t.Fatal(err)
		}
		broker.Start()
		t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
		if !broker.ReadyForConnections(5 * time.Second) {
			t.Fatal("broker did not start")
		}
		return broker
	}
	broker := start()
	states := make(chan string, 16)
	config := ServiceConnection{Servers: broker.ClientURL(), Name: "test-worker", KeyFile: keyPath, Event: func(state string) { states <- state }}
	if connection, err := ConnectService(config); err == nil {
		connection.Close()
		t.Fatal("untrusted TLS certificate accepted")
	}
	config.CAFile = caPath
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	if connection, err := ConnectService(config); err == nil {
		connection.Close()
		t.Fatal("unprotected service seed accepted")
	}
	if err := os.Chmod(keyPath, 0600); err != nil {
		t.Fatal(err)
	}
	connection, err := ConnectService(config)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	subscription, err := connection.SubscribeSync("service.test")
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	options.Port = broker.Addr().(*net.TCPAddr).Port
	broker.Shutdown()
	broker.WaitForShutdown()
	deadline := time.After(3 * time.Second)
waitDisconnect:
	for {
		select {
		case state := <-states:
			if state == "disconnected" {
				break waitDisconnect
			}
		case <-deadline:
			t.Fatal("disconnect not reported")
		}
	}
	start()
	deadline = time.After(8 * time.Second)
waitReconnect:
	for {
		select {
		case state := <-states:
			if state == "connected" {
				break waitReconnect
			}
		case <-deadline:
			t.Fatal("service key did not reconnect after broker restart")
		}
	}
	if err = connection.Publish("service.test", []byte("after restart")); err != nil {
		t.Fatal(err)
	}
	message, err := subscription.NextMsg(2 * time.Second)
	if err != nil || string(message.Data) != "after restart" {
		t.Fatal("subscriptions did not recover after NKey reconnection", err)
	}
	connection.Close()
	deadline = time.After(3 * time.Second)
	for {
		select {
		case state := <-states:
			if state == "closed" {
				return
			}
		case <-deadline:
			t.Fatal("service connection did not close")
		}
	}
}
