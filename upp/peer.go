// Package upp is the façade that orders the v1 security gates. It has exactly
// one stream API (Stream) and never derives authority from authentication or
// verification results (protocol-v1.md §6/§7).
package upp

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/IFindMe/open-upp/authz"
	"github.com/IFindMe/open-upp/discovery"
	"github.com/IFindMe/open-upp/identity"
	"github.com/IFindMe/open-upp/session"
	"github.com/IFindMe/open-upp/spec"
	"github.com/IFindMe/open-upp/transport"
	"github.com/IFindMe/open-upp/verify"
)

// Config supplies the local state and the terminal bindings for one peer.
type Config struct {
	Identity   *identity.Identity
	PinsPath   string
	GrantsPath string
	Resource   string
	// ExpectedPeerFP, when set, is an untrusted routing consistency check from
	// the hint. A mismatch is unknown_peer; it never authorizes a peer.
	ExpectedPeerFP [32]byte
	Stdout         io.Writer
	Stderr         io.Writer
	Stdin          io.Reader
}

// Peer orchestrates hint routing, handshake, verification, grant and stream.
type Peer struct {
	cfg Config
	in  *bufio.Reader
}

func New(cfg Config) (*Peer, error) {
	if cfg.Identity == nil {
		return nil, fmt.Errorf("%s: local identity is required", spec.UsageError)
	}
	if cfg.Resource == "" {
		cfg.Resource = "stream"
	}
	if cfg.Stdout == nil {
		cfg.Stdout = io.Discard
	}
	if cfg.Stderr == nil {
		cfg.Stderr = io.Discard
	}
	if cfg.Stdin == nil {
		cfg.Stdin = strings.NewReader("")
	}
	return &Peer{cfg: cfg, in: bufio.NewReader(cfg.Stdin)}, nil
}

// Reader exposes the shared buffered stdin so the CLI can read stream lines
// from the same source as the consent prompts.
func (p *Peer) Reader() *bufio.Reader { return p.in }

// HintFor builds the endpoint hint advertised by a listener.
func (p *Peer) HintFor(addr string, port uint16) discovery.Hint {
	return discovery.Hint{SubjectFP: p.cfg.Identity.Fingerprint(), Addr: addr, Port: port}
}

const confirmPrompt = "I compared the safety number above with the peer over an independent channel and it matches.\n" +
	"Type yes to continue; anything else denies: "

// readYes reads one line with a 120 s timeout. EOF, timeout, and anything but
// "yes" (case-insensitive) deny; there is no bypass flag or remembered answer.
func (p *Peer) readYes() (accepted, timedOut bool) {
	lineCh := make(chan string, 1)
	go func() {
		line, _ := p.in.ReadString('\n')
		lineCh <- line
	}()
	select {
	case line := <-lineCh:
		return strings.EqualFold(strings.TrimSpace(line), "yes"), false
	case <-time.After(120 * time.Second):
		return false, true
	}
}

func (p *Peer) prompt(text string) (bool, bool) {
	fmt.Fprint(p.cfg.Stderr, text)
	return p.readYes()
}

// declineFailure maps a prompt outcome to W4's exit codes: timeout is a
// terminal failure (1), an explicit non-yes answer is a decline (3).
func declineFailure(timedOut bool) error {
	if timedOut {
		return spec.NewFailure(spec.VerificationAborted,
			"safety-number comparison timed out or was cancelled",
			"restart and complete the out-of-band comparison")
	}
	return &spec.Failure{Token: spec.VerificationAborted, Message: "operator declined the safety-number confirmation", Exit: 3}
}

// Dial routes via a dialable endpoint and returns a stream only after every
// gate has passed. ctx is checked before routing and before handshake.
func (p *Peer) Dial(ctx context.Context, addr string) (*Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := (transport.TCP{Timeout: spec.RouteTimeoutS * time.Second}).Dial(addr)
	if err != nil {
		return nil, spec.NewFailure(spec.RouteFailed,
			"could not reach peer after 3 attempts (5s timeout each)",
			"check the -hint file and network reachability")
	}
	return p.establish(ctx, conn, true)
}

// Accept runs the gates for one inbound connection.
func (p *Peer) Accept(ctx context.Context, conn net.Conn) (*Stream, error) {
	if err := ctx.Err(); err != nil {
		conn.Close()
		return nil, err
	}
	return p.establish(ctx, conn, false)
}

func (p *Peer) establish(ctx context.Context, conn net.Conn, initiator bool) (*Stream, error) {
	var hr *session.HandshakeResult
	var err error
	if initiator {
		hr, err = session.InitiatorHandshake(conn, p.cfg.Identity)
	} else {
		hr, err = session.ResponderHandshake(conn, p.cfg.Identity)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		conn.Close()
		return nil, err
	}
	if p.cfg.ExpectedPeerFP != [32]byte{} && hr.PeerFP != p.cfg.ExpectedPeerFP {
		conn.Close()
		return nil, spec.NewFailure(spec.UnknownPeer,
			"no route or identity record matched the peer hint",
			"check -hint and -identity, then start a new attempt")
	}

	// Gate 1: OOB pairwise safety-number verification. Authentication here is
	// not verification and not authority.
	fmt.Fprintf(p.cfg.Stdout, "upp: peer authenticated: %s\n", hex.EncodeToString(hr.PeerFP[:]))
	sn := verify.Format(hr.SNDigest)
	fmt.Fprintln(p.cfg.Stdout, "upp: pairwise safety number (8-char groups):")
	fmt.Fprintf(p.cfg.Stdout, "upp:   %s\n", sn)

	stores, err := verify.Load(p.cfg.PinsPath)
	if err != nil {
		conn.Close()
		return nil, err
	}
	change := stores.Check(hr.PeerFP, hr.PeerKey)
	if change == verify.ChangeRoot {
		fmt.Fprintf(p.cfg.Stdout, "Peer root fingerprint changed. New fingerprint: %s\n", hex.EncodeToString(hr.PeerFP[:]))
		fmt.Fprintln(p.cfg.Stdout, "New pairwise safety number (8-char groups):")
		fmt.Fprintf(p.cfg.Stdout, "  %s\n", sn)
		if ok, _ := p.prompt("I compared this new number with the peer over an independent channel and it matches.\nType yes to accept the new identity; anything else denies: "); !ok {
			conn.Close()
			return nil, spec.NewFailure(spec.UnverifiedSN,
				"peer root fingerprint changed; explicit full-digest confirmation required",
				"re-verify the new identity out of band and grant it explicitly")
		}
	} else {
		if ok, timedOut := p.prompt(confirmPrompt); !ok {
			conn.Close()
			return nil, declineFailure(timedOut)
		}
	}
	if change == verify.ChangeKey {
		fmt.Fprintln(p.cfg.Stdout, "upp: key_rotated: peer presented a valid successor key; pin kept")
	}
	fmt.Fprintln(p.cfg.Stdout, "upp: verified: pairwise safety number matched on both sides")

	// Gate 2: explicit scoped grant. No path from verification to authority.
	grants, err := authz.Load(p.cfg.GrantsPath)
	if err != nil {
		conn.Close()
		return nil, err
	}
	scope, err := grants.Decide(hr.PeerFP, p.cfg.Resource, "open")
	if err != nil {
		conn.Close()
		return nil, spec.NewFailure(spec.AuthorizationDenied,
			"no enabled scoped grant covers peer "+hex.EncodeToString(hr.PeerFP[:])+" for "+p.cfg.Resource+"/open",
			"an administrator must run upp grant add; verification alone is not a grant")
	}
	fmt.Fprintf(p.cfg.Stdout, "upp: authorized: grant %s covers %s %s\n",
		scope.GrantID, scope.Resource, strings.Join(scope.Ops, ","))
	// The pin is written only after both the fresh OOB confirmation and the
	// grant decision pass; no failure above this point writes a pin. It is
	// reused as change-detection state, never as authority.
	if err := stores.Commit(hr.PeerFP, hr.PeerKey, hr.SNDigest); err != nil {
		conn.Close()
		return nil, err
	}

	// Gate 3: install keys once, then exchange SESSION_READY before data.
	s, err := hr.Derive(p.cfg.Resource)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := s.WriteRecord(conn, spec.TypeSessionReady, nil); err != nil {
		s.Zeroize()
		conn.Close()
		return nil, err
	}
	typ, _, err := s.ReadRecord(conn)
	if err != nil {
		s.Zeroize()
		conn.Close()
		return nil, err
	}
	if typ != spec.TypeSessionReady {
		s.Zeroize()
		conn.Close()
		return nil, spec.NewFailure(spec.SessionKeyError, "session keys could not be established; no stream opened", "")
	}
	openLine := "upp: session_open: stream ready (resource=" + p.cfg.Resource + ")"
	if initiator {
		openLine += "; type a line to send, Ctrl-D to close"
	}
	fmt.Fprintln(p.cfg.Stdout, openLine)

	st := &Stream{
		scope:    scope,
		peerFP:   hr.PeerFP,
		peerKey:  hr.PeerKey,
		grants:   grants,
		localID:  p.cfg.Identity,
		resource: p.cfg.Resource,
		s: &sessionRef{
			recordWriter: func(t byte, b []byte) error { return s.WriteRecord(conn, t, b) },
			recordReader: func() (byte, []byte, error) { return s.ReadRecord(conn) },
			zeroize:      func() { s.Zeroize(); conn.Close() },
		},
	}
	return st, nil
}
