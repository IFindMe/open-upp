// Package transport — Tailcat adapter (ADR-002). This is the ONLY import site
// of github.com/tailscale/tailcat in the repository: an unstable external API
// is confined to this one file so a version bump is a single-file change.
//
// A Tailcat tc... address is an opaque secret-bearer locator. It is stored
// verbatim in the 0600 hint, never interpreted, never used as identity, and
// never allowed into a diagnostic. UPP's own gates still run on the net.Conn
// this adapter yields; WireGuard here protects only the path.
package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/tailscale/tailcat"
)

// DefaultServicePort is the UPP service port inside the Tailcat tunnel when a
// caller leaves ServicePort unset.
const DefaultServicePort uint16 = 443

// Tailcat implements Transport over a tailcat.Server (listen) and a lazily
// started tailcat.Client (dial).
type Tailcat struct {
	ServicePort uint16
	Timeout     time.Duration
}

var _ Transport = Tailcat{}

func (t Tailcat) Name() string { return "tailcat" }

func (t Tailcat) servicePort() uint16 {
	if t.ServicePort == 0 {
		return DefaultServicePort
	}
	return t.ServicePort
}

// Listen starts a Tailcat server whose OnTCP handler feeds accepted UPP
// connections into a bounded channel. Connections to any other port are
// refused (nil handler => RST), so unmatched ports never reach a UPP gate.
// bind is impl-defined and ignored for Tailcat (the capability is the route).
func (t Tailcat) Listen(bind string) (Acceptor, error) {
	_ = bind
	ch := make(chan Conn, 1) // bounded: at most one conn queued for Accept
	done := make(chan struct{})
	port := t.servicePort()

	srv := &tailcat.Server{
		OnTCP: func(p uint16) func(net.Conn) {
			if p != port {
				return nil // RST for unmatched ports
			}
			return func(c net.Conn) {
				select {
				case ch <- c:
				case <-done:
					_ = c.Close()
				}
			}
		},
	}
	if err := srv.Start(); err != nil {
		close(done)
		return nil, fmt.Errorf("start tailcat server: %w", err)
	}
	// TailcatAddr embeds the server capability; it goes only into the 0600
	// hint via Acceptor.Endpoint(), never into stdout/stderr or an error.
	a := &tailcatAcceptor{
		srv:  srv,
		ch:   ch,
		done: done,
		ep:   Endpoint{Addr: string(srv.TailcatAddr()), Port: port},
	}
	return a, nil
}

// tailcatAcceptor is the listening half. The server owns the tunnel; the
// channel carries per-connection net.Conns to the UPP gate chain.
type tailcatAcceptor struct {
	srv  *tailcat.Server
	ch   chan Conn
	done chan struct{}
	ep   Endpoint
	once sync.Once
}

var _ Acceptor = (*tailcatAcceptor)(nil)

func (a *tailcatAcceptor) Accept() (Conn, error) {
	select {
	case c := <-a.ch:
		return c, nil
	case <-a.done:
		return nil, net.ErrClosed
	}
}

func (a *tailcatAcceptor) Endpoint() Endpoint { return a.ep }

func (a *tailcatAcceptor) Close() error {
	var err error
	a.once.Do(func() {
		close(a.done) // unblock any queued handler before stopping the server
		err = a.srv.Close()
	})
	return err
}

// Dial opens a TCP connection to ep.Port on the Tailcat server described by
// the opaque ep.Addr capability. ctx bounds startup and dialing. The returned
// conn's Close also closes the client, covering both possible Client.Close()
// lifetime semantics (ADR-002 §6.9). Errors never interpolate ep.Addr.
func (t Tailcat) Dial(ctx context.Context, ep Endpoint) (Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if t.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.Timeout)
		defer cancel()
	}
	client := tailcat.NewClient(tailcat.Addr(ep.Addr))
	conn, err := client.DialTCPPort(ctx, ep.Port)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("tailcat dial failed: %w", err)
	}
	return &clientConn{Conn: conn, client: client}, nil
}

// clientConn ties the tunnel connection's lifetime to its client. Closing the
// conn closes the client exactly once; the embedded net.Conn supplies all
// read/write/deadline methods unchanged.
type clientConn struct {
	net.Conn
	client *tailcat.Client
	once   sync.Once
}

func (c *clientConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		if cerr := c.client.Close(); err == nil {
			err = cerr
		}
	})
	return err
}
