// Command upp is the thin two-peer CLI for the v1 slice. It only parses flags,
// renders stable reason tokens and drives the upp façade; all crypto and state
// transitions live in the library packages.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/IFindMe/open-upp/authz"
	"github.com/IFindMe/open-upp/discovery"
	"github.com/IFindMe/open-upp/identity"
	"github.com/IFindMe/open-upp/spec"
	"github.com/IFindMe/open-upp/transport"
	"github.com/IFindMe/open-upp/upp"
	"github.com/IFindMe/open-upp/verify"
)

const usage = `upp — two-peer Open UPP (protocol v1)

Usage:
  upp listen  [-identity PATH] [-hint PATH] [-grants PATH] [-pins PATH]
              [-transport tailcat|tcp] [-service-port PORT] [-addr HOST:PORT]
  upp connect [-identity PATH] [-hint PATH] [-grants PATH] [-pins PATH]
              [-transport tailcat|tcp] [-resource NAME] [-op LIST]
  upp verify -identity PATH -peer PATH [-sn "8-char groups"]
  upp grant add    -identity PATH -grants PATH -peer-fp HEX [-resource NAME] [-op LIST]
  upp grant revoke -grants PATH (-grant-id ID | -peer-fp HEX)
  upp grant list   [-grants PATH]
  upp help

Tailcat is the default transport. -transport tcp is an explicit local-test
fallback only; it never downgrades identity, verification or grant checks.
All state files are written with mode 0600. Verification requires an explicit
out-of-band pairwise safety-number comparison on every session; authorization
requires an explicit scoped grant. Consent is per session and per grant.
`

var validOps = map[string]bool{"open": true, "read": true, "write": true}

// newFlagSet keeps flag-package diagnostics from bypassing the single W4
// usage-error renderer.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func main() {
	if len(os.Args) < 2 {
		usageExit()
	}
	var err error
	switch os.Args[1] {
	case "listen":
		err = listen(os.Args[2:])
	case "connect":
		err = connect(os.Args[2:])
	case "verify":
		err = verifyCmd(os.Args[2:])
	case "grant":
		err = grantCmd(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		usageExit()
	}
	if err != nil {
		render(err)
	}
}

func usageExit() {
	fmt.Fprint(os.Stderr, usage)
	os.Exit(2)
}

func usageErr(format string, args ...any) error {
	return &spec.Failure{Token: spec.UsageError, Message: fmt.Sprintf(format, args...) + `; run "upp help"`, Exit: 2}
}

// render is the single failure renderer: one reason token plus a secret-free
// sentence on stderr, an optional recovery line, and the W4 exit code.
func render(err error) {
	var f *spec.Failure
	if errors.As(err, &f) {
		fmt.Fprintf(os.Stderr, "upp: %s: %s\n", f.Token, f.Message)
		if f.Next != "" {
			fmt.Fprintf(os.Stderr, "  Next: %s.\n", f.Next)
		}
		os.Exit(f.Exit)
	}
	fmt.Fprintf(os.Stderr, "upp: usage error: %v; run \"upp help\"\n", err)
	os.Exit(2)
}

func loadIdentity(path string) (*identity.Identity, error) {
	id, err := identity.Load(path)
	if err != nil {
		return nil, usageErr("cannot load identity %q: %v", path, err)
	}
	return id, nil
}

func parseOps(raw string) ([]string, error) {
	if raw == "" {
		return nil, usageErr("-op must be a comma-separated subset of open,read,write")
	}
	parts := strings.Split(raw, ",")
	seen := map[string]bool{}
	for _, op := range parts {
		op = strings.TrimSpace(op)
		if !validOps[op] || seen[op] {
			return nil, usageErr("invalid or duplicate op %q", op)
		}
		seen[op] = true
	}
	return parts, nil
}

// newTransport is the sole composition point for transport selection: Tailcat
// is the default; TCP is opt-in for local testing only. There is no runtime
// auto-downgrade and the untrusted hint never selects the backend.
func newTransport(name string, servicePort uint16) (transport.Transport, error) {
	switch name {
	case discovery.TransportTailcat:
		return transport.Tailcat{ServicePort: servicePort, Timeout: spec.RouteTimeoutS * time.Second}, nil
	case discovery.TransportTCP:
		return transport.TCP{Timeout: spec.RouteTimeoutS * time.Second}, nil
	default:
		return nil, usageErr("unknown transport %q (want tailcat or tcp)", name)
	}
}

func newPeer(tr transport.Transport, id *identity.Identity, grantsPath, pinsPath, resource string, expected [32]byte) (*upp.Peer, error) {
	return upp.New(upp.Config{
		Transport:      tr,
		Identity:       id,
		PinsPath:       pinsPath,
		GrantsPath:     grantsPath,
		Resource:       resource,
		ExpectedPeerFP: expected,
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
		Stdin:          os.Stdin,
	})
}

func listen(args []string) error {
	fs := newFlagSet("listen")
	idPath := fs.String("identity", "identity.json", "local identity file")
	hintPath := fs.String("hint", "peer.hint", "endpoint hint output file")
	grantsPath := fs.String("grants", "grants.json", "local scoped grant file")
	pinsPath := fs.String("pins", "pins.json", "local pin file")
	addr := fs.String("addr", "127.0.0.1:0", "TCP fallback bind address (LAN address for the two-host case)")
	transportName := fs.String("transport", discovery.TransportTailcat, "transport: tailcat (default) or tcp (local-test only)")
	servicePort := fs.Uint("service-port", uint(transport.DefaultServicePort), "UPP service port inside the Tailcat tunnel")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if fs.NArg() != 0 {
		return usageErr("unexpected argument %q", fs.Arg(0))
	}
	id, err := loadIdentity(*idPath)
	if err != nil {
		return err
	}
	tr, err := newTransport(*transportName, uint16(*servicePort))
	if err != nil {
		return err
	}
	bind := "" // Tailcat is addressed by capability, not a bind address
	if *transportName == discovery.TransportTCP {
		bind = *addr
	}
	ln, err := tr.Listen(bind)
	if err != nil {
		return spec.NewFailure(spec.RouteFailed, "could not reach peer after 3 attempts (5s timeout each)", "check the -hint file and network reachability")
	}
	defer ln.Close()
	p, err := newPeer(tr, id, *grantsPath, *pinsPath, "stream", [32]byte{})
	if err != nil {
		return err
	}
	if err := discovery.Save(*hintPath, p.HintFor(ln.Endpoint())); err != nil {
		return usageErr("cannot write hint: %v", err)
	}
	fmt.Fprintf(os.Stdout, "upp: listening: hint written to %s\n", *hintPath)
	fmt.Fprintln(os.Stdout, "upp: waiting for peer; press Ctrl-C to stop")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	conn, err := ln.Accept()
	if err != nil {
		if ctx.Err() != nil {
			return &spec.Failure{Token: spec.VerificationAborted, Message: "safety-number comparison timed out or was cancelled", Exit: 3}
		}
		return spec.NewFailure(spec.ConnectionLost, "peer disconnected; 3 re-handshake attempts failed", "restart after connectivity is restored; new session keys will be derived")
	}
	st, err := p.Accept(ctx, conn)
	if err != nil {
		return err
	}
	defer st.Close()
	return serveEcho(ctx, p, st)
}

// serveEcho is the listener's stream behaviour: print received bytes and echo
// them back until the peer sends CLOSE, then send CLOSE ourselves.
func serveEcho(ctx context.Context, p *upp.Peer, st *upp.Stream) error {
	buf := make([]byte, 4096)
	for {
		n, err := st.Read(buf)
		if n > 0 {
			_, _ = os.Stdout.Write(buf[:n])
			if _, werr := st.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return spec.NewFailure(spec.ConnectionLost, "peer disconnected; 3 re-handshake attempts failed", "restart after connectivity is restored; new session keys will be derived")
		}
	}
	if err := st.CloseWrite(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "upp: ended: session closed; session keys zeroized")
	return nil
}

func connect(args []string) error {
	fs := newFlagSet("connect")
	idPath := fs.String("identity", "identity.json", "local identity file")
	hintPath := fs.String("hint", "peer.hint", "peer endpoint hint (read-only)")
	grantsPath := fs.String("grants", "grants.json", "local scoped grant file")
	pinsPath := fs.String("pins", "pins.json", "local pin file")
	resource := fs.String("resource", "stream", "resource to authorize")
	opRaw := fs.String("op", "open,read,write", "requested operations (subset of grant)")
	transportName := fs.String("transport", discovery.TransportTailcat, "transport: tailcat (default) or tcp (local-test only)")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if fs.NArg() != 0 {
		return usageErr("unexpected argument %q", fs.Arg(0))
	}
	if _, err := parseOps(*opRaw); err != nil {
		return err
	}
	id, err := loadIdentity(*idPath)
	if err != nil {
		return err
	}
	hint, err := discovery.Load(*hintPath)
	if err != nil {
		return usageErr("cannot load hint: %v", err)
	}
	tr, err := newTransport(*transportName, transport.DefaultServicePort)
	if err != nil {
		return err
	}
	p, err := newPeer(tr, id, *grantsPath, *pinsPath, *resource, hint.SubjectFP)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	st, err := p.Dial(ctx, transport.Endpoint{Addr: hint.Addr, Port: hint.Port})
	if err != nil {
		return err
	}
	defer st.Close()
	in := p.Reader()
	buf := make([]byte, 4096)
	for {
		line, err := in.ReadString('\n')
		if len(line) > 0 {
			if _, werr := st.Write([]byte(line)); werr != nil {
				return werr
			}
		}
		if err != nil {
			break
		}
	}
	if err := st.CloseWrite(); err != nil {
		return err
	}
	for {
		n, err := st.Read(buf)
		if n > 0 {
			_, _ = os.Stdout.Write(buf[:n])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stdout, "upp: ended: session closed; session keys zeroized")
	return nil
}

func verifyCmd(args []string) error {
	fs := newFlagSet("verify")
	idPath := fs.String("identity", "identity.json", "local identity file")
	peerPath := fs.String("peer", "", "peer identity/public record file")
	snRaw := fs.String("sn", "", "optional 52-character pairwise safety number")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if *peerPath == "" || fs.NArg() != 0 {
		return usageErr("-peer is required and no extra arguments are accepted")
	}
	local, err := loadIdentity(*idPath)
	if err != nil {
		return err
	}
	peer, err := loadIdentity(*peerPath)
	if err != nil {
		return err
	}
	localFP := local.Fingerprint()
	peerFP := peer.Fingerprint()
	fmt.Fprintf(os.Stdout, "upp: local fingerprint: %s\n", hex.EncodeToString(localFP[:]))
	fmt.Fprintf(os.Stdout, "upp: peer  fingerprint: %s\n", hex.EncodeToString(peerFP[:]))
	fmt.Fprintln(os.Stdout, "upp: pairwise safety number (8-char groups):")
	fmt.Fprintf(os.Stdout, "upp:   %s\n", identity.PairwiseSafetyNumber(localFP, peerFP))
	fmt.Fprintln(os.Stdout, "upp: compare this number with the peer over an independent channel")
	if *snRaw != "" {
		got, err := verify.ParseSN(*snRaw)
		if err != nil {
			return usageErr("%v", err)
		}
		if !verify.Equal(verify.Digest(localFP, peerFP), got) {
			return spec.NewFailure(spec.UnverifiedSN,
				"the safety numbers did not match; connection refused",
				"repeat the comparison over an independent channel")
		}
		fmt.Fprintln(os.Stdout, "upp: verified: pairwise safety number matched on both sides")
	}
	return nil
}

func grantCmd(args []string) error {
	if len(args) == 0 {
		return usageErr("grant requires add, revoke or list")
	}
	switch args[0] {
	case "add":
		return grantAdd(args[1:])
	case "revoke":
		return grantRevoke(args[1:])
	case "list":
		return grantList(args[1:])
	default:
		return usageErr("unknown grant subcommand %q", args[0])
	}
}

func grantAdd(args []string) error {
	fs := newFlagSet("grant add")
	idPath := fs.String("identity", "identity.json", "local identity file")
	grantsPath := fs.String("grants", "grants.json", "local scoped grant file")
	peerFP := fs.String("peer-fp", "", "full 64-hex peer fingerprint")
	resource := fs.String("resource", "stream", "resource to grant")
	opRaw := fs.String("op", "open,read,write", "operations to grant")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if fs.NArg() != 0 {
		return usageErr("unexpected argument %q", fs.Arg(0))
	}
	raw, err := hex.DecodeString(*peerFP)
	if err != nil || len(raw) != 32 || strings.ToLower(*peerFP) != hex.EncodeToString(raw) {
		return usageErr("-peer-fp must be the full 64-character lowercase hex fingerprint")
	}
	ops, err := parseOps(*opRaw)
	if err != nil {
		return err
	}
	var subject [32]byte
	copy(subject[:], raw)
	fmt.Fprintf(os.Stderr, "Grant to peer %s for resource %q, ops %s.\n", hex.EncodeToString(raw), *resource, strings.Join(ops, ","))
	fmt.Fprint(os.Stderr, "Type yes to grant; anything else denies: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if !strings.EqualFold(strings.TrimSpace(line), "yes") {
		return &spec.Failure{Token: spec.AuthorizationDenied, Message: "operator declined the scoped grant", Exit: 3}
	}
	id, err := loadIdentity(*idPath)
	if err != nil {
		return err
	}
	g, err := authz.NewGrant(id, subject, *resource, ops)
	if err != nil {
		return err
	}
	store, err := authz.Load(*grantsPath)
	if err != nil {
		return usageErr("cannot load grants: %v", err)
	}
	if err := store.Add(*g); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "upp: granted: grant %s for %s %s %s\n", g.ID, g.SubjectFP, g.Resource, strings.Join(g.Ops, ","))
	return nil
}

func grantRevoke(args []string) error {
	fs := newFlagSet("grant revoke")
	grantsPath := fs.String("grants", "grants.json", "local scoped grant file")
	grantID := fs.String("grant-id", "", "grant id to disable")
	peerFP := fs.String("peer-fp", "", "disable all grants for this peer fingerprint")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if fs.NArg() != 0 {
		return usageErr("unexpected argument %q", fs.Arg(0))
	}
	if (*grantID == "") == (*peerFP == "") {
		return usageErr("exactly one of -grant-id or -peer-fp is required")
	}
	store, err := authz.Load(*grantsPath)
	if err != nil {
		return usageErr("cannot load grants: %v", err)
	}
	if *grantID != "" {
		if err := store.Revoke(*grantID); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "upp: revoked: grant %s disabled\n", *grantID)
		return nil
	}
	count := 0
	for _, g := range store.List() {
		if g.SubjectFP == *peerFP {
			if err := store.Revoke(g.ID); err != nil {
				return err
			}
			count++
		}
	}
	fmt.Fprintf(os.Stdout, "upp: revoked: %d grant(s) disabled for %s\n", count, *peerFP)
	return nil
}

func grantList(args []string) error {
	fs := newFlagSet("grant list")
	grantsPath := fs.String("grants", "grants.json", "local scoped grant file")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if fs.NArg() != 0 {
		return usageErr("unexpected argument %q", fs.Arg(0))
	}
	store, err := authz.Load(*grantsPath)
	if err != nil {
		return usageErr("cannot load grants: %v", err)
	}
	for _, g := range store.List() {
		fmt.Fprintf(os.Stdout, "upp: grant %s %s %s %s enabled=%t\n",
			g.ID, g.SubjectFP, g.Resource, strings.Join(g.Ops, ","), g.Enabled)
	}
	return nil
}
