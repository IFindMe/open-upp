package upp

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IFindMe/open-upp/authz"
	"github.com/IFindMe/open-upp/identity"
	"github.com/IFindMe/open-upp/spec"
	"github.com/IFindMe/open-upp/transport"
)

// epFor converts a loopback TCP test listener into the widened endpoint. These
// tests exercise the explicit TCP fallback, not Tailcat/DERP.
func epFor(t *testing.T, ln net.Listener) transport.Endpoint {
	t.Helper()
	return transport.Endpoint{Addr: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port)}
}

// smokeConfig builds one side of the two-peer smoke test. Consent is supplied
// through the same stdin prompt path the CLI uses; no bypass flag exists.
func smokeConfig(id *identity.Identity, dir, grants, pins string, expected [32]byte) Config {
	return Config{
		Transport:      transport.TCP{},
		Identity:       id,
		GrantsPath:     filepath.Join(dir, grants),
		PinsPath:       filepath.Join(dir, pins),
		Resource:       "stream",
		ExpectedPeerFP: expected,
		Stdin:          strings.NewReader("yes\n"),
		Stdout:         io.Discard,
		Stderr:         io.Discard,
	}
}

func grantFor(t *testing.T, path string, authority *identity.Identity, subject [32]byte) {
	t.Helper()
	g, err := authz.NewGrant(authority, subject, "stream", []string{"open", "read", "write"})
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
}

// TestTwoPeerSmoke is a minimal end-to-end compile/behavior check for the
// happy path and the no-grant denial. The comprehensive matrix is Tester's W7.
func TestTwoPeerSmoke(t *testing.T) {
	dir := t.TempDir()
	alice, err := identity.Create("device")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := identity.Create("device")
	if err != nil {
		t.Fatal(err)
	}
	aliceFP, bobFP := alice.Fingerprint(), bob.Fingerprint()
	grantFor(t, filepath.Join(dir, "alice.grants"), alice, bobFP)
	grantFor(t, filepath.Join(dir, "bob.grants"), bob, aliceFP)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	server, err := New(smokeConfig(alice, dir, "alice.grants", "alice.pins", [32]byte{}))
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(smokeConfig(bob, dir, "bob.grants", "bob.pins", aliceFP))
	if err != nil {
		t.Fatal(err)
	}

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		st, err := server.Accept(context.Background(), conn)
		if err != nil {
			serverDone <- err
			return
		}
		defer st.Close()
		buf := make([]byte, 64)
		for {
			n, readErr := st.Read(buf)
			if n > 0 {
				if _, werr := st.Write(buf[:n]); werr != nil {
					serverDone <- werr
					return
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				serverDone <- readErr
				return
			}
		}
		serverDone <- st.CloseWrite()
	}()

	st, err := client.Dial(context.Background(), epFor(t, ln))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := st.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := st.Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("echo = %q, err = %v", buf[:n], err)
	}
	for {
		_, err = st.Read(buf)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}

	// No grant is ever inferred from verification, fingerprint or transport.
	store, err := authz.Load(filepath.Join(dir, "empty.grants"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(bobFP, "stream", "open"); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("unguarded decision = %v, want ErrDenied", err)
	}
}

// TestNoGrantDenied verifies the gate fails at authorization, not earlier.
func TestNoGrantDenied(t *testing.T) {
	dir := t.TempDir()
	alice, _ := identity.Create("device")
	bob, _ := identity.Create("device")
	grantFor(t, filepath.Join(dir, "alice.grants"), alice, bob.Fingerprint())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		server, _ := New(smokeConfig(alice, dir, "alice.grants", "server.pins", [32]byte{}))
		if st, err := server.Accept(context.Background(), conn); err == nil {
			st.Close()
		}
	}()

	client, err := New(smokeConfig(bob, dir, "missing.grants", "client.pins", alice.Fingerprint()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Dial(context.Background(), epFor(t, ln))
	var f *spec.Failure
	if !errors.As(err, &f) || f.Token != spec.AuthorizationDenied {
		t.Fatalf("error = %v, want authorization_denied", err)
	}
}
