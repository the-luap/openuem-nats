// Package smtptransport bounds an entire SMTP exchange, including greetings,
// authentication, DATA replies and QUIT, with the caller's operation context.
package smtptransport

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
)

type Dialer struct {
	ctx         context.Context
	cancel      context.CancelFunc
	tls         *tls.Config
	mu          sync.Mutex
	closed      bool
	connections []net.Conn
	stops       []func() bool
}

// New optionally enables TLS before the SMTP greeting. STARTTLS callers pass
// nil and let the mail library upgrade the same underlying connection.
func New(ctx context.Context, implicitTLS *tls.Config) *Dialer {
	if implicitTLS != nil {
		implicitTLS = implicitTLS.Clone()
	}
	operation, cancel := context.WithCancel(ctx)
	return &Dialer{ctx: operation, cancel: cancel, tls: implicitTLS}
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := d.ctx.Err(); err != nil {
		return nil, err
	}
	dialCtx, cancelDial := context.WithCancel(ctx)
	stopDial := context.AfterFunc(d.ctx, cancelDial)
	defer stopDial()
	defer cancelDial()
	var connection net.Conn
	var err error
	if d.tls != nil {
		dialer := tls.Dialer{Config: d.tls}
		connection, err = dialer.DialContext(dialCtx, network, address)
	} else {
		dialer := net.Dialer{}
		connection, err = dialer.DialContext(dialCtx, network, address)
	}
	if err != nil {
		return nil, err
	}
	// Keep the actual *tls.Conn type visible to SMTP's authentication checks.
	// Closing the socket also interrupts a subsequent STARTTLS wrapper and
	// defeats library calls which extend the socket's per-command deadline.
	stop := context.AfterFunc(d.ctx, func() { connection.Close() })
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.ctx.Err() != nil {
		stop()
		connection.Close()
		if err := d.ctx.Err(); err != nil {
			return nil, err
		}
		return nil, net.ErrClosed
	}
	d.connections = append(d.connections, connection)
	d.stops = append(d.stops, stop)
	return connection, nil
}

// Close releases failed handshakes/authentication sessions as well as successful
// sessions, and removes cancellation hooks. It is safe to call more than once.
func (d *Dialer) Close() {
	d.cancel()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	for i, connection := range d.connections {
		d.stops[i]()
		connection.Close()
	}
	d.connections = nil
	d.stops = nil
}
