package nats

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
)

type AgentConnection struct {
	Endpoint    string
	DeviceID    string
	BrokerKey   nkeys.KeyPair
	Roots       *x509.CertPool
	Certificate *tls.Certificate
	// Event receives state names only, never credential-bearing library errors.
	Event        func(string)
	ErrorHandler nats.ErrHandler
}

func (config AgentConnection) options() ([]nats.Option, error) {
	u, err := url.Parse(config.Endpoint)
	if err != nil || u.Scheme != "wss" || u.Hostname() == "" || u.User != nil || u.Path != "/agent-channel" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || config.BrokerKey == nil {
		return nil, errors.New("agent connection requires a credential-free WSS agent-channel endpoint and an individual key")
	}
	prefix, err := enrollment.ReplyPrefix(config.DeviceID)
	if err != nil {
		return nil, err
	}
	public, err := config.BrokerKey.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		return nil, errors.New("individual agent broker key is invalid")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: config.Roots}
	if config.Certificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*config.Certificate}
	}
	event := func(value string) {
		if config.Event != nil {
			config.Event(value)
		}
	}
	options := []nats.Option{
		nats.Secure(tlsConfig), nats.Nkey(public, config.BrokerKey.Sign),
		nats.CustomInboxPrefix(prefix), nats.Name("openuem-agent:" + config.DeviceID),
		nats.Timeout(10 * time.Second), nats.MaxReconnects(-1), nats.ReconnectWait(2 * time.Second),
		// Broker-discovered addresses must never route around the gateway.
		nats.IgnoreDiscoveredServers(), nats.PingInterval(25 * time.Second), nats.MaxPingsOutstanding(3),
		nats.ReconnectHandler(func(*nats.Conn) { event("connected") }),
		nats.DisconnectErrHandler(func(*nats.Conn, error) { event("disconnected") }),
		nats.ClosedHandler(func(*nats.Conn) { event("closed") }),
	}
	if config.ErrorHandler != nil {
		options = append(options, nats.ErrorHandler(config.ErrorHandler))
	}
	return options, nil
}

// ConnectAgent uses the explicit gateway path, nonce proof and a private inbox.
// It never falls back to an unauthenticated transport or a shared identity.
func ConnectAgent(config AgentConnection) (*nats.Conn, error) {
	options, err := config.options()
	if err != nil {
		return nil, err
	}
	connection, err := nats.Connect(config.Endpoint, options...)
	if err != nil {
		return nil, err
	}
	if config.Event != nil {
		config.Event("connected")
	}
	return connection, nil
}
