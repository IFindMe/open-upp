package transport

// C5 transport-interface conformance (ADR-002 §2.1, §6.3). These tests are
// deterministic and network-independent: they exercise the explicit TCP
// fallback, which shares the exact widened seam that Tailcat implements.
// Endpoint abstraction, context-aware Dial, the Name() routing selector and
// capability-safe diagnostics are verified here; the Tailcat-specific live
// lifecycle is in tailcat_c5_test.go.

import (
	"context"
	"testing"
	"time"
)

func TestTransportNameSelectorC5(t *testing.T) {
	// Name is a routing discriminator only, never a trust signal.
	if got := (TCP{}).Name(); got != "tcp" {
		t.Fatalf("TCP.Name() = %q, want tcp", got)
	}
	if got := (Tailcat{}).Name(); got != "tailcat" {
		t.Fatalf("Tailcat.Name() = %q, want tailcat", got)
	}
}

func TestInterfaceConformanceC5(t *testing.T) {
	// Compile-time assertions in the production files are the real guard; this
	// test pins the concrete types used by the CLI so a seam widening cannot
	// silently drop an implementation.
	var tr Transport = TCP{}
	if tr.Name() != "tcp" {
		t.Fatal("TCP no longer satisfies Transport with name tcp")
	}
	tr = Tailcat{}
	if tr.Name() != "tailcat" {
		t.Fatal("Tailcat no longer satisfies Transport with name tailcat")
	}
}

func TestTCPEndpointRoundTripC5(t *testing.T) {
	// The widened Acceptor.Endpoint() must round-trip into Dial(ctx, Endpoint).
	ln, err := (TCP{}).Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ep := ln.Endpoint()
	if ep.Port == 0 {
		t.Fatal("TCP acceptor returned port 0")
	}
	if ep.Addr == "" {
		t.Fatal("TCP acceptor returned empty address")
	}

	served := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			served <- e
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, e := c.Read(buf)
		if e != nil {
			served <- e
			return
		}
		_, e = c.Write(buf[:n])
		served <- e
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := (TCP{}).Dial(ctx, ep)
	if err != nil {
		t.Fatalf("Dial(ctx, Endpoint()) = %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("roundtrip")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "roundtrip" {
		t.Fatalf("echo = %q, err = %v", buf[:n], err)
	}
	if err := <-served; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

func TestTCPDialHonorsContextC5(t *testing.T) {
	// Dial must take a context and honor cancellation (no blocking fallback).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := (TCP{}).Dial(ctx, Endpoint{Addr: "127.0.0.1", Port: 9})
	if err == nil {
		t.Fatal("Dial with cancelled context unexpectedly succeeded")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Dial ignored context cancellation (took %s)", elapsed)
	}
}

// Note: the TCP fallback's Addr is a plain host, not a tc... capability, so
// the capability-hygiene assertion belongs to the Tailcat adapter and to the
// upp boundary (see tailcat_c5_test.go and capability_gate_c5_test.go). The
// low-level net.Dialer may echo a failed hostname in its own error; upp.Dial
// always replaces transport errors with the secret-free route_failed token.
