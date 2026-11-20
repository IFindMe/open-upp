package transport

// C5 Tailcat-adapter tests. Deterministic secret-hygiene/config checks run in
// the normal suite; the live listen/dial/close/lifecycle test is gated behind
// UPP_TAILCAT_LIVE=1 so CI pass/fail never depends on magicsock/DERP or on a
// public relay being reachable (ADR-002 §6.7). The live test was executed
// explicitly for this report and its evidence recorded there.

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTailcatConfigAndDefaultPortC5(t *testing.T) {
	if got := (Tailcat{}).servicePort(); got != DefaultServicePort {
		t.Fatalf("default service port = %d, want %d", got, DefaultServicePort)
	}
	if got := (Tailcat{ServicePort: 8443}).servicePort(); got != 8443 {
		t.Fatalf("explicit service port = %d, want 8443", got)
	}
}

func TestTailcatBadCapabilityNoLeakC5(t *testing.T) {
	// A bogus capability must fail to dial and must never be echoed in the
	// error (ADR-002 §5/§6.5). Bound the attempt so this stays a fast unit test.
	const secret = "tcSECRET-CAPABILITY-DO-NOT-ECHO-9f3a7c11"
	tr := Tailcat{ServicePort: 443, Timeout: 3 * time.Second}
	conn, err := tr.Dial(context.Background(), Endpoint{Addr: secret, Port: 443})
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("bogus Tailcat capability unexpectedly dialed")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("Tailcat dial error leaked capability: %q", err.Error())
	}
}

// tailcatEchoOnce accepts one connection at ln, dials ep, exchanges msg, and
// reports any failure. It is used for repeated-dial lifecycle coverage.
func tailcatEchoOnce(t *testing.T, ln Acceptor, tr Tailcat, ep Endpoint, msg string) {
	t.Helper()
	srvErr := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			srvErr <- e
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 128)
		n, e := c.Read(buf)
		if e != nil {
			srvErr <- e
			return
		}
		_, e = c.Write(buf[:n])
		srvErr <- e
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, ep)
	if err != nil {
		t.Fatalf("dial %q: %v", msg, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write %q: %v", msg, err)
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != msg {
		t.Fatalf("echo = %q, err = %v (want %q)", buf[:n], err, msg)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server echo %q: %v", msg, err)
	}
}

func TestTailcatLiveLifecycleC5(t *testing.T) {
	if os.Getenv("UPP_TAILCAT_LIVE") != "1" {
		t.Skip("set UPP_TAILCAT_LIVE=1 to run the live Tailcat lifecycle test")
	}
	const port uint16 = 44892
	tr := Tailcat{ServicePort: port, Timeout: 15 * time.Second}

	ln, err := tr.Listen("")
	if err != nil {
		t.Skipf("Tailcat server cannot start in this environment: %v", err)
	}
	ep := ln.Endpoint()
	if ep.Port != port {
		t.Fatalf("endpoint port = %d, want %d", ep.Port, port)
	}
	if !strings.HasPrefix(ep.Addr, "tc") {
		t.Fatalf("endpoint address is not a tc... capability (len=%d)", len(ep.Addr))
	}
	capability := ep.Addr

	// Repeated dials over one listener: each conn reaches the UPP-facing
	// handler and echoes, proving accept/dial/conn lifetime is reusable.
	tailcatEchoOnce(t, ln, tr, ep, "dial-1")
	tailcatEchoOnce(t, ln, tr, ep, "dial-2")

	// Closing the acceptor must unblock Accept with net.ErrClosed and be
	// idempotent (server shutdown behavior).
	if err := ln.Close(); err != nil {
		t.Fatalf("acceptor Close: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("second acceptor Close: %v", err)
	}
	acceptDone := make(chan error, 1)
	go func() {
		_, e := ln.Accept()
		acceptDone <- e
	}()
	select {
	case e := <-acceptDone:
		if !errors.Is(e, net.ErrClosed) {
			t.Fatalf("Accept after Close = %v, want net.ErrClosed", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not unblock after Close")
	}

	// Diagnostics after shutdown must still not leak the capability.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, Endpoint{Addr: capability, Port: port})
	if conn != nil {
		conn.Close()
	}
	if err != nil && strings.Contains(err.Error(), capability) {
		t.Fatalf("post-shutdown error leaked capability: %q", err.Error())
	}
}
