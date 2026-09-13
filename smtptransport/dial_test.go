package smtptransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOperationCancellationInterruptsStalledSMTPAfterDialContextEnds(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- connection
		}
	}()
	operation, cancelOperation := context.WithCancel(t.Context())
	defer cancelOperation()
	dialer := New(operation, nil)
	defer dialer.Close()
	connect, cancelConnect := context.WithCancel(operation)
	connection, err := dialer.DialContext(connect, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	defer server.Close()
	cancelConnect() // A mail library may release its dial-only context after AUTH.
	if _, err = server.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err = connection.Read(buffer); err != nil {
		t.Fatal("dial context incorrectly closed the whole SMTP operation")
	}
	finished := make(chan error, 1)
	go func() { _, err := connection.Read(buffer); finished <- err }()
	cancelOperation()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("cancelled SMTP read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("stalled SMTP read ignored cancellation")
	}
}

func TestImplicitTLSKeepsVerifiedConnectionTypeAndCleanup(t *testing.T) {
	source := httptest.NewTLSServer(nil)
	certificate := source.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(source.Certificate())
	source.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		connection, err := listener.Accept()
		if err == nil {
			defer connection.Close()
			connection.SetDeadline(time.Now().Add(3 * time.Second))
			buffer := make([]byte, 1)
			connection.Read(buffer)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	dialer := New(ctx, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
	connection, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	secure, ok := connection.(*tls.Conn)
	if !ok || !secure.ConnectionState().HandshakeComplete {
		t.Fatal("SMTP cannot verify the TLS connection")
	}
	dialer.Close()
	dialer.Close()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("SMTP cleanup did not close its connection")
	}
	if _, err = dialer.DialContext(ctx, "tcp", listener.Addr().String()); err == nil {
		t.Fatal("closed SMTP dialer accepted another connection")
	}
}
