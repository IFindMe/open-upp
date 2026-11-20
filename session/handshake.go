package session

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net"
	"time"

	"github.com/IFindMe/open-upp/identity"
	"github.com/IFindMe/open-upp/spec"
	"github.com/IFindMe/open-upp/wire"
)

// Role records which side of the X25519 exchange produced the session keys.
type Role int

const (
	RoleInitiator Role = iota // sent HELLO / FINISHED
	RoleResponder             // sent HELLO_RESPONSE
)

// HandshakeResult is the authenticated-but-unverified, unauthorized binding
// produced by the handshake. It holds no traffic key. Verification, grant and
// Derive() are separate, ordered gates in the upp façade.
type HandshakeResult struct {
	Role       Role
	LocalID    *identity.Identity
	LocalFP    [32]byte
	PeerFP     [32]byte
	PeerKey    []byte
	PeerRecord *identity.Identity
	TH         [32]byte
	ECDH       []byte
	SNDigest   [32]byte
}

type handshake struct {
	conn      net.Conn
	id        *identity.Identity
	challenge [32]byte
	issuedAt  time.Time
	used      bool
	ephPriv   *ecdh.PrivateKey
	ephPub    []byte
}

func newHandshake(conn net.Conn, id *identity.Identity) (*handshake, error) {
	if id == nil {
		return nil, errors.New("nil identity")
	}
	if err := id.Verify(); err != nil {
		return nil, spec.NewFailure(spec.BadProof, "local identity failed verification; no session was created", "check the local identity file")
	}
	if id.IsRevoked(id.CurrentKey()) {
		return nil, spec.NewFailure(spec.Revoked, "peer key is on the local deny list; session terminated", "rotate the peer identity key, then start a new attempt")
	}
	h := &handshake{conn: conn, id: id}
	if _, err := rand.Read(h.challenge[:]); err != nil {
		return nil, err
	}
	h.issuedAt = time.Now()
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	h.ephPriv = priv
	h.ephPub = priv.PublicKey().Bytes()
	return h, nil
}

func (h *handshake) withDeadline(fn func() (*HandshakeResult, error)) (*HandshakeResult, error) {
	if err := h.conn.SetDeadline(time.Now().Add(spec.HandshakeTimeoutS * time.Second)); err != nil {
		return nil, err
	}
	defer h.conn.SetDeadline(time.Time{})
	return fn()
}

// checkChallenge consumes the local challenge used by the peer's PoP. It is
// single-use and must be within the frozen 60 s freshness window.
func (h *handshake) checkChallenge(peerChallenge []byte) error {
	if h.used {
		return spec.NewFailure(spec.StaleChallenge, "handshake challenge was reused or outside the 60s window", "start a new handshake with a fresh challenge")
	}
	if !bytes.Equal(h.challenge[:], peerChallenge) {
		return spec.NewFailure(spec.StaleChallenge, "handshake challenge was reused or outside the 60s window", "start a new handshake with a fresh challenge")
	}
	if time.Since(h.issuedAt) > spec.FreshnessWindowS*time.Second {
		return spec.NewFailure(spec.StaleChallenge, "handshake challenge was reused or outside the 60s window", "start a new handshake with a fresh challenge")
	}
	h.used = true
	return nil
}

func transcriptHash(helloRaw, helloResponseWithoutPop []byte) [32]byte {
	return sha256.Sum256(spec.Canon(helloRaw, helloResponseWithoutPop))
}

func popBlob(cPeer, cLocal, ephLocal, ephPeer []byte, th [32]byte) []byte {
	return spec.Canon([]byte(spec.TagHandshakePoP), cPeer, cLocal, ephLocal, ephPeer, th[:])
}

func rejectVersion() error {
	return spec.NewFailure(spec.VersionRejected,
		"peer offered an unsupported version, suite or extension; no fallback attempted", "")
}

func connectionLost() error {
	return spec.NewFailure(spec.ConnectionLost,
		"peer disconnected; 3 re-handshake attempts failed",
		"restart after connectivity is restored; new session keys will be derived")
}

func writeFrame(conn net.Conn, payload []byte) error {
	frame, err := spec.EncodeFrame(payload)
	if err != nil {
		return err
	}
	if _, err := conn.Write(frame); err != nil {
		return connectionLost()
	}
	return nil
}

func readFrame(conn net.Conn) ([]byte, error) {
	payload, err := spec.DecodeFrame(conn)
	if err != nil {
		return nil, connectionLost()
	}
	return payload, nil
}

func (h *handshake) decodePeerRecord(raw []byte) (*identity.Identity, error) {
	peer, err := identity.DecodePublicRecord(raw)
	if err != nil {
		return nil, spec.NewFailure(spec.BadProof, "peer identity proof failed verification; no session was created", "discard this attempt and start a fresh handshake; check both identity files")
	}
	if err := peer.Verify(); err != nil {
		return nil, spec.NewFailure(spec.BadProof, "peer identity proof failed verification; no session was created", "discard this attempt and start a fresh handshake; check both identity files")
	}
	if len(peer.CurrentKey()) != 32 || h.id.IsRevoked(peer.CurrentKey()) {
		return nil, spec.NewFailure(spec.Revoked, "peer key is on the local deny list; session terminated", "rotate the peer identity key, then start a new attempt")
	}
	return peer, nil
}

func (h *handshake) result(peer *identity.Identity, th [32]byte, shared []byte, role Role) *HandshakeResult {
	localFP := h.id.Fingerprint()
	peerFP := peer.Fingerprint()
	return &HandshakeResult{
		Role:       role,
		LocalID:    h.id,
		LocalFP:    localFP,
		PeerFP:     peerFP,
		PeerKey:    peer.CurrentKey(),
		PeerRecord: peer,
		TH:         th,
		ECDH:       bytes.Clone(shared),
		SNDigest:   identity.PairwiseSafetyDigest(localFP, peerFP),
	}
}

// InitiatorHandshake runs HELLO -> HELLO_RESPONSE -> FINISHED and returns the
// authenticated binding. No session key is derived here.
func InitiatorHandshake(conn net.Conn, id *identity.Identity) (*HandshakeResult, error) {
	h, err := newHandshake(conn, id)
	if err != nil {
		return nil, err
	}
	return h.withDeadline(func() (*HandshakeResult, error) {
		record, err := id.EncodePublicRecord()
		if err != nil {
			return nil, err
		}
		helloRaw, err := wire.BuildHello(wire.Hello{
			Version: spec.Version, SuiteSet: spec.SuiteSet,
			Challenge: h.challenge[:], EPHPub: h.ephPub, Record: record,
		})
		if err != nil {
			return nil, err
		}
		if err := writeFrame(conn, helloRaw); err != nil {
			return nil, err
		}
		respRaw, err := readFrame(conn)
		if err != nil {
			return nil, err
		}
		resp, respPrefix, err := wire.ParseHelloResponse(respRaw)
		if err != nil {
			return nil, rejectVersion()
		}
		peer, err := h.decodePeerRecord(resp.Record)
		if err != nil {
			return nil, err
		}
		th := transcriptHash(helloRaw, respPrefix)
		// B's PoP binds A's challenge (c_peer for B), B's own challenge, and
		// the two ephemerals in the exact published order.
		popB := popBlob(h.challenge[:], resp.Challenge, resp.EPHPub, h.ephPub, th)
		if !peer.VerifyChallenge(peer.CurrentKey(), popB, resp.Pop) {
			return nil, spec.NewFailure(spec.BadProof, "peer identity proof failed verification; no session was created", "discard this attempt and start a fresh handshake; check both identity files")
		}
		if err := h.checkChallenge(h.challenge[:]); err != nil {
			return nil, err
		}
		peerEph, err := ecdh.X25519().NewPublicKey(resp.EPHPub)
		if err != nil {
			return nil, spec.NewFailure(spec.BadProof, "peer identity proof failed verification; no session was created", "discard this attempt and start a fresh handshake; check both identity files")
		}
		shared, err := h.ephPriv.ECDH(peerEph)
		if err != nil {
			return nil, spec.NewFailure(spec.BadProof, "peer identity proof failed verification; no session was created", "discard this attempt and start a fresh handshake; check both identity files")
		}
		popA, err := id.SignChallenge(popBlob(resp.Challenge, h.challenge[:], h.ephPub, resp.EPHPub, th))
		if err != nil {
			return nil, err
		}
		finished, err := wire.BuildFinished(wire.Finished{Pop: popA})
		if err != nil {
			return nil, err
		}
		if err := writeFrame(conn, finished); err != nil {
			return nil, err
		}
		return h.result(peer, th, shared, RoleInitiator), nil
	})
}

// ResponderHandshake reads HELLO, emits HELLO_RESPONSE with its own PoP, then
// verifies FINISHED. No session key is derived here.
func ResponderHandshake(conn net.Conn, id *identity.Identity) (*HandshakeResult, error) {
	h, err := newHandshake(conn, id)
	if err != nil {
		return nil, err
	}
	return h.withDeadline(func() (*HandshakeResult, error) {
		helloRaw, err := readFrame(conn)
		if err != nil {
			return nil, err
		}
		hello, _, err := wire.ParseHello(helloRaw)
		if err != nil {
			return nil, rejectVersion()
		}
		peer, err := h.decodePeerRecord(hello.Record)
		if err != nil {
			return nil, err
		}
		record, err := id.EncodePublicRecord()
		if err != nil {
			return nil, err
		}
		resp, respPrefix, err := wire.BuildHelloResponse(wire.HelloResponse{
			Version: spec.Version, Suite: spec.Suite,
			Challenge: h.challenge[:], EPHPub: h.ephPub, Record: record,
			Pop: make([]byte, 64),
		})
		if err != nil {
			return nil, err
		}
		_ = resp
		th := transcriptHash(helloRaw, respPrefix)
		popB, err := id.SignChallenge(popBlob(hello.Challenge, h.challenge[:], h.ephPub, hello.EPHPub, th))
		if err != nil {
			return nil, err
		}
		resp, _, err = wire.BuildHelloResponse(wire.HelloResponse{
			Version: spec.Version, Suite: spec.Suite,
			Challenge: h.challenge[:], EPHPub: h.ephPub, Record: record,
			Pop: popB,
		})
		if err != nil {
			return nil, err
		}
		if err := writeFrame(conn, resp); err != nil {
			return nil, err
		}
		finishedRaw, err := readFrame(conn)
		if err != nil {
			return nil, err
		}
		finished, err := wire.ParseFinished(finishedRaw)
		if err != nil {
			return nil, rejectVersion()
		}
		popA := popBlob(h.challenge[:], hello.Challenge, hello.EPHPub, h.ephPub, th)
		if !peer.VerifyChallenge(peer.CurrentKey(), popA, finished.Pop) {
			return nil, spec.NewFailure(spec.BadProof, "peer identity proof failed verification; no session was created", "discard this attempt and start a fresh handshake; check both identity files")
		}
		if err := h.checkChallenge(h.challenge[:]); err != nil {
			return nil, err
		}
		peerEph, err := ecdh.X25519().NewPublicKey(hello.EPHPub)
		if err != nil {
			return nil, spec.NewFailure(spec.BadProof, "peer identity proof failed verification; no session was created", "discard this attempt and start a fresh handshake; check both identity files")
		}
		shared, err := h.ephPriv.ECDH(peerEph)
		if err != nil {
			return nil, spec.NewFailure(spec.BadProof, "peer identity proof failed verification; no session was created", "discard this attempt and start a fresh handshake; check both identity files")
		}
		return h.result(peer, th, shared, RoleResponder), nil
	})
}
