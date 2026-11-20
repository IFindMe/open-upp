// Package transport provides the UPP-neutral transport seam and its two
// implementations: Tailcat (the default connectivity core) and TCP (an
// explicit local-test fallback). Protection terminates at the UPP peers above
// this layer; a transport or relay never sees plaintext (W3 D3, ADR-002).
package transport

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

// Conn is an ordinary net.Conn; the AEAD record layer is written above it.
// Both Tailcat's DialTCPPort and the TCP adapter yield a net.Conn.
type Conn = net.Conn

// Endpoint is a UPP-neutral locator. Addr is opaque: a tc... capability for
// Tailcat, or a host for the explicit TCP fallback. UPP stores and passes it
// verbatim and never derives identity or authority from it (ADR-002 §3/§5).
type Endpoint struct {
	Addr string
	Port uint16
}

// Acceptor is the listening side of the transport seam. Endpoint replaces the
// old Addr() net.Addr: a tc... capability is not a net.Addr.
type Acceptor interface {
	Accept() (Conn, error)
	Endpoint() Endpoint
	Close() error
}

// Transport is the seam implemented by Tailcat and the TCP fallback. Name is a
// routing selector only; it confers no trust. Dial takes a context so the UPP
// route timeout is honored by both implementations.
type Transport interface {
	Name() string
	Listen(bind string) (Acceptor, error)
	Dial(ctx context.Context, ep Endpoint) (Conn, error)
}

// TCP is the explicit loopback/LAN implementation used for local testing and
// CI comparison only. It is never selected by automatic downgrade (ADR-002).
type TCP struct {
	Timeout time.Duration
}

var _ Transport = TCP{}

func (t TCP) Name() string { return "tcp" }

func (t TCP) Listen(bind string) (Acceptor, error) {
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		// bind is a local configuration value, not a capability; keep the
		// diagnostic generic nonetheless (ADR-002 §6.5).
		return nil, fmt.Errorf("tcp listen failed: %w", err)
	}
	return &tcpAcceptor{TCPListener: ln.(*net.TCPListener)}, nil
}

// tcpAcceptor adapts net.TCPListener to the widened Acceptor contract.
type tcpAcceptor struct {
	*net.TCPListener
}

var _ Acceptor = (*tcpAcceptor)(nil)

func (a *tcpAcceptor) Endpoint() Endpoint {
	ta := a.Addr().(*net.TCPAddr)
	host := ta.IP.String()
	if host == "::" || host == "" {
		host = "127.0.0.1"
	}
	return Endpoint{Addr: host, Port: uint16(ta.Port)}
}

func (t TCP) Dial(ctx context.Context, ep Endpoint) (Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if t.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.Timeout)
		defer cancel()
	}
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ep.Addr, strconv.Itoa(int(ep.Port))))
	if err != nil {
		// Addr is never interpolated into an error (capability hygiene).
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}
	return conn, nil
}
