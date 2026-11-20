// Package transport provides the TCP implementation and the Tailcat seam for
// the v1 slice. Protection terminates at the UPP peers above this layer; a
// transport or relay never sees plaintext (W3 D3, protocol-v1.md §10).
package transport

import (
	"fmt"
	"net"
	"time"
)

// Conn is an ordinary net.Conn; the AEAD record layer is written above it.
type Conn = net.Conn

// Acceptor is the listening side of the transport seam.
type Acceptor interface {
	Accept() (Conn, error)
	Close() error
	Addr() net.Addr
}

// Transport is the seam a future Tailcat adapter can implement.
type Transport interface {
	Listen(addr string) (Acceptor, error)
	Dial(addr string) (Conn, error)
}

// TCP is the loopback/LAN implementation used by the two-peer slice.
type TCP struct {
	Timeout time.Duration
}

func (t TCP) Listen(addr string) (Acceptor, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	return ln, nil
}

func (t TCP) Dial(addr string) (Conn, error) {
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return conn, nil
}
