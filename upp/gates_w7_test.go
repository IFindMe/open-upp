package upp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IFindMe/open-upp/authz"
	"github.com/IFindMe/open-upp/identity"
	"github.com/IFindMe/open-upp/spec"
)

func cfgFor(id *identity.Identity, dir, grant, pins, consent string, expected [32]byte, out io.Writer) Config {
	return Config{
		Identity:       id,
		GrantsPath:     filepath.Join(dir, grant),
		PinsPath:       filepath.Join(dir, pins),
		Resource:       "stream",
		ExpectedPeerFP: expected,
		Stdin:          strings.NewReader(consent),
		Stdout:         out,
		Stderr:         io.Discard,
	}
}

// dialPair runs one loopback pair. serverBody, if set, drives the accepted
// stream; otherwise the server closes it after establishment. The returned
// channel reports the server-side result so callers can drive the client first.
func dialPair(t *testing.T, sc, cc Config, serverBody func(*Stream) error) (*Stream, error, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}
	res := make(chan error, 1)
	go func() {
		conn, e := ln.Accept()
		if e != nil {
			res <- e
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
	st, ce := client.Dial(context.Background(), ln.Addr().String())
	if ce != nil {
		ln.Close() // unblock Accept if the client never connected
	}
	return st, ce, res
}

func addGrant(t *testing.T, path string, authority *identity.Identity, subject [32]byte, ops []string) string {
	t.Helper()
	g, err := authz.NewGrant(authority, subject, "stream", ops)
	if err != nil {
		t.Fatal(err)
	}
	s, err := authz.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(*g); err != nil {
		t.Fatal(err)
	}
	return g.ID
}

func failure(t *testing.T, err error) *spec.Failure {
	t.Helper()
	var f *spec.Failure
	if !errors.As(err, &f) {
		t.Fatalf("error %v is not *spec.Failure", err)
	}
	return f
}

func setupIDs(t *testing.T, dir string) (*identity.Identity, *identity.Identity) {
	t.Helper()
	a, _ := identity.Create("device")
	b, _ := identity.Create("device")
	return a, b
}

// TestGrantGateAfterVerificationNoPinOnDenial proves the gate ordering:
// handshake + verification happen first, but with no grant there is no
// authorization line, no session_open, and no pin is committed.
func TestGrantGateAfterVerificationNoPinOnDenial(t *testing.T) {
	dir := t.TempDir()
	serverID, clientID := setupIDs(t, dir)
	serverFP := serverID.Fingerprint()

	var sOut, cOut bytes.Buffer
	sc := cfgFor(serverID, dir, "server.grants", "server.pins", "yes\n", [32]byte{}, &sOut)
	cc := cfgFor(clientID, dir, "client.empty.grants", "client.pins", "yes\n", serverFP, &cOut)

	_, ce, _ := dialPair(t, sc, cc, nil)
	if ce == nil {
		t.Fatal("no-grant client unexpectedly established a stream")
	}
	if got := failure(t, ce); got.Token != spec.AuthorizationDenied {
		t.Fatalf("token = %q, want authorization_denied", got.Token)
	}
	assertContains(t, cOut.String(), "upp: peer authenticated:", "upp: pairwise safety number (8-char groups):", "upp: verified:")
	assertNotContains(t, cOut.String(), "upp: authorized:", "upp: session_open:")
	if _, err := os.Stat(filepath.Join(dir, "client.pins")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pin written despite grant denial")
	}
}

// TestVerificationGateBeforeGrantAndSession proves that declining the OOB SN
// prompt stops before the grant/session gates, even with a valid grant present.
func TestVerificationGateBeforeGrantAndSession(t *testing.T) {
	dir := t.TempDir()
	serverID, clientID := setupIDs(t, dir)
	serverFP := serverID.Fingerprint()
	clientFP := clientID.Fingerprint()
	addGrant(t, filepath.Join(dir, "server.grants"), serverID, clientFP, []string{"open", "read", "write"})
	addGrant(t, filepath.Join(dir, "client.grants"), clientID, serverFP, []string{"open", "read", "write"})

	var sOut, cOut bytes.Buffer
	sc := cfgFor(serverID, dir, "server.grants", "server.pins", "yes\n", [32]byte{}, &sOut)
	cc := cfgFor(clientID, dir, "client.grants", "client.pins", "no\n", serverFP, &cOut)

	_, ce, _ := dialPair(t, sc, cc, nil)
	f := failure(t, ce)
	if f.Token != spec.VerificationAborted || f.Exit != 3 {
		t.Fatalf("token/exit = %q/%d, want verification_aborted/3", f.Token, f.Exit)
	}
	assertContains(t, cOut.String(), "upp: peer authenticated:")
	assertNotContains(t, cOut.String(), "upp: verified:", "upp: authorized:", "upp: session_open:")
	// Pins are per-peer change-detection state: the declining client writes none.
	// The server verifies independently and may commit its own pin; that pin is
	// never authority and its session still fails without the peer's SESSION_READY.
	if _, err := os.Stat(filepath.Join(dir, "client.pins")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("client pin written despite declined verification")
	}
}

// TestNoSessionBeforeMutualPoP: a peer key on the local deny list fails the
// handshake, so no grant decision, key derivation, or pin occurs.
func TestNoSessionBeforeMutualPoP(t *testing.T) {
	dir := t.TempDir()
	serverID, clientID := setupIDs(t, dir)
	clientFP := clientID.Fingerprint()
	addGrant(t, filepath.Join(dir, "server.grants"), serverID, clientFP, []string{"open", "read", "write"})
	addGrant(t, filepath.Join(dir, "client.grants"), clientID, serverID.Fingerprint(), []string{"open", "read", "write"})
	if err := clientID.RevokeKey(serverID.CurrentKey()); err != nil {
		t.Fatal(err)
	}

	var sOut, cOut bytes.Buffer
	sc := cfgFor(serverID, dir, "server.grants", "server.pins", "yes\n", [32]byte{}, &sOut)
	cc := cfgFor(clientID, dir, "client.grants", "client.pins", "yes\n", serverID.Fingerprint(), &cOut)

	_, ce, _ := dialPair(t, sc, cc, nil)
	if got := failure(t, ce); got.Token != spec.Revoked {
		t.Fatalf("token = %q, want revoked", got.Token)
	}
	assertNotContains(t, cOut.String(), "upp: verified:", "upp: authorized:", "upp: session_open:")
	if _, err := os.Stat(filepath.Join(dir, "client.pins")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pin written after failed handshake")
	}
}

// TestHappyPathPinCommittedAndStreamClose exercises session readiness, one
// stream, echo, graceful close, and that the pin is written only on success.
func TestHappyPathPinCommittedAndStreamClose(t *testing.T) {
	dir := t.TempDir()
	serverID, clientID := setupIDs(t, dir)
	serverFP, clientFP := serverID.Fingerprint(), clientID.Fingerprint()
	addGrant(t, filepath.Join(dir, "server.grants"), serverID, clientFP, []string{"open", "read", "write"})
	addGrant(t, filepath.Join(dir, "client.grants"), clientID, serverFP, []string{"open", "read", "write"})

	var sOut, cOut bytes.Buffer
	sc := cfgFor(serverID, dir, "server.grants", "server.pins", "yes\n", [32]byte{}, &sOut)
	cc := cfgFor(clientID, dir, "client.grants", "client.pins", "yes\n", serverFP, &cOut)

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
	st, ce, srvRes := dialPair(t, sc, cc, echo)
	if ce != nil {
		t.Fatalf("client establish failed: %v", ce)
	}
	defer st.Close()

	if n, err := st.Write([]byte("ping")); err != nil || n != 4 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if err := st.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := st.Read(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("echo = %q, err %v", buf[:n], err)
	}
	if _, err := st.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("graceful close = %v, want io.EOF", err)
	}
	if st.Scope().Resource != "stream" {
		t.Fatal("stream scope wrong")
	}
	assertContains(t, cOut.String(), "upp: verified:", "upp: authorized:", "upp: session_open:")
	if _, err := os.Stat(filepath.Join(dir, "client.pins")); err != nil {
		t.Fatalf("pin not written on success: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("after-close")); !errors.Is(err, io.EOF) {
		t.Fatal("write after close did not fail")
	}
	if se := <-srvRes; se != nil {
		t.Fatalf("server echo failed: %v", se)
	}
}

// TestPerOpScopeRecheck: a grant covering only open+read cannot write; the
// denial happens at the per-op decision on Stream.Write.
func TestPerOpScopeRecheck(t *testing.T) {
	dir := t.TempDir()
	serverID, clientID := setupIDs(t, dir)
	serverFP, clientFP := serverID.Fingerprint(), clientID.Fingerprint()
	addGrant(t, filepath.Join(dir, "server.grants"), serverID, clientFP, []string{"open", "read", "write"})
	// client grant has no "write"
	addGrant(t, filepath.Join(dir, "client.grants"), clientID, serverFP, []string{"open", "read"})

	var sOut, cOut bytes.Buffer
	sc := cfgFor(serverID, dir, "server.grants", "server.pins", "yes\n", [32]byte{}, &sOut)
	cc := cfgFor(clientID, dir, "client.grants", "client.pins", "yes\n", serverFP, &cOut)
	st, ce, _ := dialPair(t, sc, cc, nil)
	if ce != nil {
		t.Fatalf("client establish failed: %v", ce)
	}
	defer st.Close()
	_, err := st.Write([]byte("not-allowed"))
	if got := failure(t, err); got.Token != spec.ScopeViolation {
		t.Fatalf("token = %q, want scope_violation", got.Token)
	}
}

// TestLiveRevocationTerminatesStream: locally revoking the peer key after the
// stream is open makes the next read/write fail with revoked.
func TestLiveRevocationTerminatesStream(t *testing.T) {
	dir := t.TempDir()
	serverID, clientID := setupIDs(t, dir)
	serverFP, clientFP := serverID.Fingerprint(), clientID.Fingerprint()
	addGrant(t, filepath.Join(dir, "server.grants"), serverID, clientFP, []string{"open", "read", "write"})
	addGrant(t, filepath.Join(dir, "client.grants"), clientID, serverFP, []string{"open", "read", "write"})

	var sOut, cOut bytes.Buffer
	sc := cfgFor(serverID, dir, "server.grants", "server.pins", "yes\n", [32]byte{}, &sOut)
	cc := cfgFor(clientID, dir, "client.grants", "client.pins", "yes\n", serverFP, &cOut)
	st, ce, _ := dialPair(t, sc, cc, func(st *Stream) error {
		buf := make([]byte, 64)
		_, _ = st.Read(buf) // wait for client data/close
		return st.CloseWrite()
	})
	if ce != nil {
		t.Fatalf("client establish failed: %v", ce)
	}
	defer st.Close()
	if err := clientID.RevokeKey(serverID.CurrentKey()); err != nil {
		t.Fatal(err)
	}
	_, err := st.Write([]byte("after-revoke"))
	if got := failure(t, err); got.Token != spec.Revoked {
		t.Fatalf("token = %q, want revoked", got.Token)
	}
}

func assertContains(t *testing.T, s string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(s, p) {
			t.Fatalf("output missing %q; got:\n%s", p, s)
		}
	}
}

func assertNotContains(t *testing.T, s string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if strings.Contains(s, p) {
			t.Fatalf("output unexpectedly contains %q; got:\n%s", p, s)
		}
	}
}
