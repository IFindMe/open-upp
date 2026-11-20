package session

import (
	"bytes"
	"errors"
	"io"

	"github.com/IFindMe/open-upp/spec"
)

// writeFrameTo and readFrameFrom are the io-based frame primitives used by the
// record layer; the handshake uses the net.Conn wrappers in handshake.go.
func writeFrameTo(w io.Writer, payload []byte) error {
	frame, err := spec.EncodeFrame(payload)
	if err != nil {
		return err
	}
	_, err = w.Write(frame)
	return err
}

func readFrameFrom(r io.Reader) ([]byte, error) {
	return spec.DecodeFrame(r)
}

// Session is an installed, direction-separated AEAD record stream. Keys exist
// only after the verification and grant gates have passed in the façade.
type Session struct {
	th       [32]byte
	send     *cipherState
	recv     *cipherState
	resource string
	role     Role
	zeroized bool
}

// Derive installs traffic keys from the handshake binding. It is intentionally
// a separate step so the handshake itself can never reach a keyed state.
func (h *HandshakeResult) Derive(resource string) (*Session, error) {
	if h == nil || len(h.ECDH) != 32 {
		return nil, spec.NewFailure(spec.SessionKeyError, "session keys could not be established; no stream opened", "")
	}
	lo, hi := h.LocalFP, h.PeerFP
	if bytes.Compare(lo[:], hi[:]) > 0 {
		lo, hi = hi, lo
	}
	info := spec.Canon([]byte(spec.TagSessionKDF), lo[:], hi[:])
	okm, err := spec.HKDF(h.TH[:], h.ECDH, info, 72)
	if err != nil {
		return nil, spec.NewFailure(spec.SessionKeyError, "session keys could not be established; no stream opened", "")
	}
	c2s, err := newCipherState(okm[0:32], okm[64:68])
	if err != nil {
		return nil, spec.NewFailure(spec.SessionKeyError, "session keys could not be established; no stream opened", "")
	}
	s2c, err := newCipherState(okm[32:64], okm[68:72])
	if err != nil {
		return nil, spec.NewFailure(spec.SessionKeyError, "session keys could not be established; no stream opened", "")
	}
	s := &Session{th: h.TH, resource: resource, role: h.Role}
	if h.Role == RoleInitiator {
		s.send, s.recv = c2s, s2c
	} else {
		s.send, s.recv = s2c, c2s
	}
	for i := range okm {
		okm[i] = 0
	}
	for i := range h.ECDH {
		h.ECDH[i] = 0
	}
	return s, nil
}

func opForType(t byte) string {
	switch t {
	case spec.TypeSessionReady:
		return "session_ready"
	case spec.TypeData:
		return "write"
	case spec.TypeClose:
		return "close"
	default:
		return ""
	}
}

// WriteRecord seals one AEAD record with the next send sequence number.
func (s *Session) WriteRecord(w io.Writer, typ byte, plaintext []byte) error {
	if s == nil || s.zeroized || s.send == nil {
		return errors.New("session is closed")
	}
	fields, err := s.send.sealRecord(s.th, s.resource, opForType(typ), plaintext)
	if err != nil {
		return err
	}
	payload := append([]byte{typ}, fields...)
	return writeFrameTo(w, payload)
}

// ReadRecord reads one AEAD record, enforcing strict per-direction sequence
// numbers. CLOSE records carry a reason token as their plaintext.
func (s *Session) ReadRecord(r io.Reader) (byte, []byte, error) {
	if s == nil || s.zeroized || s.recv == nil {
		return 0, nil, errors.New("session is closed")
	}
	payload, err := readFrameFrom(r)
	if err != nil {
		return 0, nil, spec.NewFailure(spec.ConnectionLost, "peer disconnected; 3 re-handshake attempts failed", "restart after connectivity is restored; new session keys will be derived")
	}
	if len(payload) == 0 {
		return 0, nil, errors.New("empty session record")
	}
	typ := payload[0]
	if opForType(typ) == "" {
		return 0, nil, spec.NewFailure(spec.VersionRejected, "peer offered an unsupported version, suite or extension; no fallback attempted", "")
	}
	plaintext, err := s.recv.openRecord(s.th, s.resource, opForType(typ), payload[1:])
	if err != nil {
		return 0, nil, err
	}
	return typ, plaintext, nil
}

// Zeroize discards all traffic keys and sequence state. It is called on close,
// failure, loss and revocation; keys are never reused.
func (s *Session) Zeroize() {
	if s == nil || s.zeroized {
		return
	}
	s.send.zeroize()
	s.recv.zeroize()
	for i := range s.th {
		s.th[i] = 0
	}
	s.zeroized = true
}
