package nats

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment/keyfile"
)

// ServiceConnection is for trusted, private services. Device software must use
// ConnectAgent and its individual identity instead of a service seed.
type ServiceConnection struct {
	Servers, Name               string
	KeyFile, CAFile             string
	CertificateFile, TLSKeyFile string
	Event                       func(string)
	ErrorHandler                nats.ErrHandler
}

func ValidServiceURLs(value string) bool {
	addresses := strings.Split(value, ",")
	if len(addresses) > 16 {
		return false
	}
	for _, address := range addresses {
		u, err := url.Parse(address)
		if err != nil || u.Scheme != "tls" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
			return false
		}
	}
	return true
}

func servicePublicFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("service TLS file unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		return nil, errors.New("invalid service TLS file")
	}
	return data, nil
}

// ConnectService verifies TLS and NKey proof without discovering alternative
// brokers or falling back to legacy certificate authentication. It retains the
// private seed only for this connection's lifetime, including reconnections.
func ConnectService(config ServiceConnection) (*nats.Conn, error) {
	if !ValidServiceURLs(config.Servers) || config.Name == "" || len(config.Name) > 128 || strings.ContainsAny(config.Name, "\r\n") {
		return nil, errors.New("explicit TLS service origins and a service name are required")
	}
	seed, err := keyfile.Read(config.KeyFile, 512)
	if err != nil {
		return nil, errors.New("service key is unavailable or insufficiently protected")
	}
	key, err := nkeys.FromSeed(bytes.TrimSpace(seed))
	clear(seed)
	if err != nil {
		return nil, errors.New("invalid service NKey seed")
	}
	wipe := sync.OnceFunc(key.Wipe)
	connected := false
	defer func() {
		if !connected {
			wipe()
		}
	}()
	public, err := key.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		return nil, errors.New("service requires a user NKey seed")
	}
	trust := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.CAFile != "" {
		ca, err := servicePublicFile(config.CAFile, 1<<20)
		if err != nil {
			return nil, err
		}
		trust.RootCAs = x509.NewCertPool()
		if !trust.RootCAs.AppendCertsFromPEM(ca) {
			return nil, errors.New("service trust file contains no certificates")
		}
	}
	if config.CertificateFile != "" || config.TLSKeyFile != "" {
		certificate, err := servicePublicFile(config.CertificateFile, 64<<10)
		if err != nil {
			return nil, err
		}
		private, err := keyfile.Read(config.TLSKeyFile, 32<<10)
		if err != nil {
			return nil, errors.New("service TLS key is unavailable or insufficiently protected")
		}
		defer clear(private)
		pair, err := tls.X509KeyPair(certificate, private)
		if err != nil {
			return nil, errors.New("invalid service TLS identity")
		}
		trust.Certificates = []tls.Certificate{pair}
	}
	event := func(state string) {
		if config.Event != nil {
			config.Event(state)
		}
	}
	connection, err := nats.Connect(config.Servers,
		nats.Secure(trust), nats.Nkey(public, key.Sign), nats.Name(config.Name),
		nats.Timeout(3*time.Second), nats.MaxReconnects(-1), nats.ReconnectWait(2*time.Second), nats.IgnoreDiscoveredServers(),
		nats.ReconnectHandler(func(*nats.Conn) { event("connected") }),
		nats.DisconnectErrHandler(func(*nats.Conn, error) { event("disconnected") }),
		nats.ClosedHandler(func(*nats.Conn) { wipe(); event("closed") }),
		nats.ErrorHandler(func(connection *nats.Conn, subscription *nats.Subscription, err error) {
			if config.ErrorHandler != nil {
				config.ErrorHandler(connection, subscription, err)
			} else {
				event("messaging_failed")
			}
		}),
	)
	if err != nil {
		return nil, errors.New("private service broker connection failed")
	}
	connected = true
	event("connected")
	return connection, nil
}
