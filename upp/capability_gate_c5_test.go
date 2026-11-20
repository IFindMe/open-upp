package upp

// C5 decisive gate-regression matrix (ADR-002 §7, C2 §5). A stranger holding a
// VALID Tailcat capability reaches the listener (a real net.Conn is handed to
// the gate chain) but can do nothing until mutual PoP, a fresh out-of-band
// full-digest pairwise confirmation (no TOFU), and an explicit enabled in-scope
// scoped grant all pass. The fake transport below models only reachability; all
// gate logic is the frozen production establish().

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IFindMe/open-upp/authz"
	"github.com/IFindMe/open-upp/identity"
	"github.com/IFindMe/open-upp/spec"
	"github.com/IFindMe/open-upp/transport"
	"github.com/IFindMe/open-upp/verify"
)

const (
	strangerCapability = "tcSTRANGER-CAPABILITY-REACHES-LISTENER-aa11bb22cc33dd44ee55ff6677889900"
	capA               = "tcCAPABILITY-ALPHA-00112233445566778899aabbccddeeff"
	capB               = "tcCAPABILITY-BETA-ffeeddccbbaa99887766554433221100"
)

// capabilityTransport simulates a valid Tailcat route: Dial(ctx, Endpoint)
// returns a live net.Conn to a loopback listener whose accepted end is handed
// to the gate chain. Real TCP conns (rather than net.Pipe) are used so the
// synchronous handshake writes of both peers cannot deadlock. It models
// reachability ONLY: it stamps the "tailcat" name and passes the opaque
// capability verbatim without ever inspecting it.
type capabilityTransport struct {
	name     string
	ln       net.Listener
	srvConns chan net.Conn
	mu       sync.Mutex
	lastEP   transport.Endpoint
}

var _ transport.Transport = (*capabilityTransport)(nil)

func newCapabilityTransport(t *testing.T, name string) *capabilityTransport {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &capabilityTransport{name: name, ln: ln, srvConns: make(chan net.Conn, 4)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.srvConns <- conn
		}
	}()
	return c
}

func (c *capabilityTransport) Name() string { return c.name }

func (c *capabilityTransport) Listen(string) (transport.Acceptor, error) {
	return nil, errors.New("capabilityTransport.Listen is not used in gate regression")
}

func (c *capabilityTransport) Dial(ctx context.Context, ep transport.Endpoint) (transport.Conn, error) {
	c.mu.Lock()
	c.lastEP = ep
	c.mu.Unlock()
	var d net.Dialer
	return d.DialContext(ctx, "tcp", c.ln.Addr().String())
}

func (c *capabilityTransport) endpoint() transport.Endpoint {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastEP
}

func serverGateFailure(t *testing.T, res <-chan error) *spec.Failure {
	t.Helper()
	select {
	case err := <-res:
		if err == nil {
			t.Fatal("server gate unexpectedly succeeded")
		}
		return failure(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server gate result timed out")
		return nil
	}
}

func capConfig(id *identity.Identity, dir, grants, pins, consent string, expected [32]byte, out io.Writer) Config {
	return Config{
		Identity:       id,
		GrantsPath:     filepath.Join(dir, grants),
		PinsPath:       filepath.Join(dir, pins),
		Resource:       "stream",
		ExpectedPeerFP: expected,
		Stdin:          strings.NewReader(consent),
		Stdout:         out,
		Stderr:         io.Discard,
	}
}

// dialPairViaCapability runs one gate pair over a simulated Tailcat conn.
func dialPairViaCapability(t *testing.T, sc, cc Config, capability string, serverBody func(*Stream) error) (*Stream, error, <-chan error) {
	t.Helper()
	tr := newCapabilityTransport(t, "tailcat")
	sc.Transport = tr
	cc.Transport = tr

	server, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}
	res := make(chan error, 1)
	go func() {
		var conn net.Conn
		select {
		case conn = <-tr.srvConns:
		case <-time.After(10 * time.Second):
			res <- errors.New("no capability dial reached the listener")
			return
		}
		st, e := server.Accept(context.Background(), conn)
		if e != nil {
			res <- e
			return
		}
		if serverBody != nil {
			res <- serverBody(st)
		} else {
			res <- st.Close()
		}
	}()

	client, err := New(cc)
	if err != nil {
		t.Fatal(err)
	}
	st, ce := client.Dial(context.Background(), transport.Endpoint{Addr: capability, Port: 443})
	return st, ce, res
}

// assertNoCapabilityInDir proves the secret capability never lands in any
// on-disk security artifact (pins/grants/hints) during a denied session.
func assertNoCapabilityInDir(t *testing.T, dir, capability string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), capability) {
			t.Fatalf("capability leaked into state file %q", e.Name())
		}
	}
}

func TestCapabilityOnlyWithoutValidIdentityDeniedC5(t *testing.T) {
	// Capability-only reachability with a key the peer refuses (no mutual
	// PoP) must fail at the handshake, before verification/grant/session.
	dir := t.TempDir()
	serverID, clientID := setupIDs(t, dir)
	addGrant(t, filepath.Join(dir, "server.grants"), serverID, clientID.Fingerprint(), []string{"open", "read", "write"})
	if err := clientID.RevokeKey(serverID.CurrentKey()); err != nil {
		t.Fatal(err)
	}
	var sOut, cOut bytes.Buffer
	sc := capConfig(serverID, dir, "server.grants", "server.pins", "yes\n", [32]byte{}, &sOut)
	cc := capConfig(clientID, dir, "client.grants", "client.pins", "yes\n", serverID.Fingerprint(), &cOut)

	st, ce, _ := dialPairViaCapability(t, sc, cc, strangerCapability, nil)
	if st != nil {
		st.Close()
	}
	if ce == nil {
		t.Fatal("capability-only dial with bad PoP unexpectedly established")
	}
	if got := failure(t, ce); got.Token != spec.Revoked {
		t.Fatalf("token = %q, want revoked (mutual PoP gate)", got.Token)
	}
	assertNotContains(t, cOut.String(), "upp: verified:", "upp: authorized:", "upp: session_open:")
	if _, err := os.Stat(filepath.Join(dir, "client.pins")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pin written after failed mutual PoP")
	}
	assertNoCapabilityInDir(t, dir, strangerCapability)
}

func TestCapabilityVerifiedButUnguardedDeniedC5(t *testing.T) {
	// A fully verified stranger with a valid capability and NO grant is denied
	// at gate 2: verification never confers authority.
	dir := t.TempDir()
	serverID, clientID := setupIDs(t, dir)
	addGrant(t, filepath.Join(dir, "client.grants"), clientID, serverID.Fingerprint(), []string{"open", "read", "write"})
	var sOut, cOut bytes.Buffer
	sc := capConfig(serverID, dir, "server.missing.grants", "server.pins", "yes\n", [32]byte{}, &sOut)
	cc := capConfig(clientID, dir, "client.grants", "client.pins", "yes\n", serverID.Fingerprint(), &cOut)

	st, _, res := dialPairViaCapability(t, sc, cc, strangerCapability, nil)
	if st != nil {
		st.Close()
	}
	// The listener — not the dialer — owns the missing grant and denies.
	if got := serverGateFailure(t, res); got.Token != spec.AuthorizationDenied {
		t.Fatalf("server token = %q, want authorization_denied", got.Token)
	}
	assertContains(t, sOut.String(), "upp: peer authenticated:", "upp: verified:")
	assertNotContains(t, sOut.String(), "upp: authorized:", "upp: session_open:")
	assertNotContains(t, cOut.String(), strangerCapability)
	assertNotContains(t, sOut.String(), strangerCapability)
	if _, err := os.Stat(filepath.Join(dir, "server.pins")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("listener pin written despite grant denial")
	}
	assertNoCapabilityInDir(t, dir, strangerCapability)
}

func TestCapabilityRevokedGrantDeniedC5(t *testing.T) {
	// A previously granted peer whose grant is disabled is denied on a NEW
	// session even though its capability and identity remain valid.
	dir := t.TempDir()
	serverID, clientID := setupIDs(t, dir)
	gid := addGrant(t, filepath.Join(dir, "server.grants"), serverID, clientID.Fingerprint(), []string{"open", "read", "write"})
	addGrant(t, filepath.Join(dir, "client.grants"), clientID, serverID.Fingerprint(), []string{"open", "read", "write"})
	store, err := authz.Load(filepath.Join(dir, "server.grants"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(gid); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}
	var sOut, cOut bytes.Buffer
	sc := capConfig(serverID, dir, "server.grants", "server.pins", "yes\n", [32]byte{}, &sOut)
	cc := capConfig(clientID, dir, "client.grants", "client.pins", "yes\n", serverID.Fingerprint(), &cOut)

	st, _, res := dialPairViaCapability(t, sc, cc, strangerCapability, nil)
	if st != nil {
		st.Close()
	}
	if got := serverGateFailure(t, res); got.Token != spec.AuthorizationDenied {
		t.Fatalf("server token = %q, want authorization_denied", got.Token)
	}
	assertNotContains(t, sOut.String(), "upp: authorized:", "upp: session_open:")
	assertNoCapabilityInDir(t, dir, strangerCapability)
}

func TestCapabilityRootChangeRequiresReverifyC5(t *testing.T) {
	// A peer root change, wrapping a valid capability and a valid grant, still
	// requires fresh full-digest confirmation: declining must deny with no
	// TOFU/degraded path and no pin overwrite.
	dir := t.TempDir()
	oldRoot, _ := identity.Create("device")
	serverID, clientID := setupIDs(t, dir)

	stores, err := verify.Load(filepath.Join(dir, "client.pins"))
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	if err := stores.Commit(oldRoot.Fingerprint(), oldRoot.CurrentKey(), digest); err != nil {
		t.Fatal(err)
	}
	addGrant(t, filepath.Join(dir, "server.grants"), serverID, clientID.Fingerprint(), []string{"open", "read", "write"})
	addGrant(t, filepath.Join(dir, "client.grants"), clientID, serverID.Fingerprint(), []string{"open", "read", "write"})

	var sOut, cOut bytes.Buffer
	sc := capConfig(serverID, dir, "server.grants", "server.pins", "yes\n", [32]byte{}, &sOut)
	cc := capConfig(clientID, dir, "client.grants", "client.pins", "no\n", serverID.Fingerprint(), &cOut)

	st, ce, _ := dialPairViaCapability(t, sc, cc, strangerCapability, nil)
	if st != nil {
		st.Close()
	}
	if ce == nil {
		t.Fatal("root change with declined confirmation established a stream")
	}
	if got := failure(t, ce); got.Token != spec.UnverifiedSN {
		t.Fatalf("token = %q, want unverified_safety_number", got.Token)
	}
	assertContains(t, cOut.String(), "Peer root fingerprint changed")
	assertNotContains(t, cOut.String(), "upp: verified:", "upp: authorized:", "upp: session_open:")

	pinData, err := os.ReadFile(filepath.Join(dir, "client.pins"))
	if err != nil {
		t.Fatal(err)
	}
	newServerFP := serverID.Fingerprint()
	if strings.Contains(string(pinData), hex.EncodeToString(newServerFP[:])) {
		t.Fatal("new root pin committed despite declined re-verification")
	}
	assertNoCapabilityInDir(t, dir, strangerCapability)
}

func TestCapabilityHappyPathAllGatesC5(t *testing.T) {
	// With mutual PoP + fresh OOB confirmation + an explicit grant, the same
	// capability reaches session_open and echo: reachability works, authority
	// is granted only after every gate.
	dir := t.TempDir()
	serverID, clientID := setupIDs(t, dir)
	serverFP, clientFP := serverID.Fingerprint(), clientID.Fingerprint()
	addGrant(t, filepath.Join(dir, "server.grants"), serverID, clientFP, []string{"open", "read", "write"})
	addGrant(t, filepath.Join(dir, "client.grants"), clientID, serverFP, []string{"open", "read", "write"})

	var sOut, cOut bytes.Buffer
	sc := capConfig(serverID, dir, "server.grants", "server.pins", "yes\n", [32]byte{}, &sOut)
	cc := capConfig(clientID, dir, "client.grants", "client.pins", "yes\n", serverFP, &cOut)
	echo := func(st *Stream) error {
		buf := make([]byte, 64)
		n, err := st.Read(buf)
		if err != nil {
			return err
		}
		if _, err := st.Write(buf[:n]); err != nil {
			return err
		}
		return st.CloseWrite()
	}

	st, ce, srvRes := dialPairViaCapability(t, sc, cc, strangerCapability, echo)
	if ce != nil {
		t.Fatalf("establish failed: %v", ce)
	}
	defer st.Close()
	if _, err := st.Write([]byte("authorized-echo")); err != nil {
		t.Fatal(err)
	}
	if err := st.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := st.Read(buf)
	if err != nil || string(buf[:n]) != "authorized-echo" {
		t.Fatalf("echo = %q, err = %v", buf[:n], err)
	}
	assertContains(t, cOut.String(), "upp: verified:", "upp: authorized:", "upp: session_open:")
	assertNotContains(t, cOut.String(), strangerCapability)
	assertNoCapabilityInDir(t, dir, strangerCapability)
	st.Close()
	if err := <-srvRes; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

// failingTransport injects a Tailcat-style dial error that deliberately
// carries the capability, to prove the upp boundary never propagates it.
type failingTransport struct{ secret string }

func (f failingTransport) Name() string { return "tailcat" }
func (f failingTransport) Listen(string) (transport.Acceptor, error) {
	return nil, errors.New("unused")
}
func (f failingTransport) Dial(context.Context, transport.Endpoint) (transport.Conn, error) {
	return nil, fmt.Errorf("tailcat dial failed: %s", f.secret)
}

func TestRouteFailureSanitizedNoDowngradeC5(t *testing.T) {
	// A failed Tailcat dial yields the generic route_failed token; the raw
	// transport error (and any capability in it) is not surfaced, and no
	// alternate backend is attempted.
	const secret = "tcCAPABILITY-MUST-NOT-LEAK-ffeedd"
	id, err := identity.Create("device")
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{Transport: failingTransport{secret: secret}, Identity: id, Resource: "stream"})
	if err != nil {
		t.Fatal(err)
	}
	_, dialErr := p.Dial(context.Background(), transport.Endpoint{Addr: secret, Port: 443})
	if dialErr == nil {
		t.Fatal("expected route failure")
	}
	f := failure(t, dialErr)
	if f.Token != spec.RouteFailed {
		t.Fatalf("token = %q, want route_failed", f.Token)
	}
	if strings.Contains(f.Error(), secret) {
		t.Fatalf("route_failed leaked capability: %q", f.Error())
	}
}

func TestHintForDoesNotDeriveIdentityFromCapabilityC5(t *testing.T) {
	// HintFor stamps the transport discriminator from the injected backend and
	// copies the capability verbatim. SubjectFP comes from identity alone; two
	// different capabilities cannot change it and are not fingerprints.
	id, err := identity.Create("device")
	if err != nil {
		t.Fatal(err)
	}
	tr := &capabilityTransport{name: "tailcat"}
	p, err := New(Config{Transport: tr, Identity: id, Resource: "stream"})
	if err != nil {
		t.Fatal(err)
	}
	h1 := p.HintFor(transport.Endpoint{Addr: capA, Port: 443})
	h2 := p.HintFor(transport.Endpoint{Addr: capB, Port: 443})
	if h1.SubjectFP != id.Fingerprint() || h2.SubjectFP != id.Fingerprint() || h1.SubjectFP != h2.SubjectFP {
		t.Fatal("SubjectFP is not derived solely from local identity")
	}
	if h1.Addr != capA || h2.Addr != capB || h1.Port != 443 || h2.Port != 443 {
		t.Fatal("capability/endpoint not copied verbatim into hint")
	}
	if h1.Transport != "tailcat" || h2.Transport != "tailcat" {
		t.Fatalf("transport discriminator = %q/%q, want tailcat", h1.Transport, h2.Transport)
	}
	tr.name = "tcp"
	if got := p.HintFor(transport.Endpoint{Addr: "127.0.0.1", Port: 1}).Transport; got != "tcp" {
		t.Fatalf("transport discriminator = %q, want tcp", got)
	}
	for _, cap := range []string{capA, capB, strangerCapability} {
		raw, err := hex.DecodeString(cap)
		if err == nil && len(raw) == 32 {
			t.Fatalf("capability %q is also a valid identity fingerprint", cap)
		}
	}
}
