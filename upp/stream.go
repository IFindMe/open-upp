package upp

import (
	"errors"
	"io"

	"github.com/IFindMe/open-upp/authz"
	"github.com/IFindMe/open-upp/identity"
	"github.com/IFindMe/open-upp/spec"
)

// Stream is the single application-level byte-stream API of the v1 slice.
// It implements io.ReadWriteCloser and re-checks the scoped grant on every
// read and write; revocation takes effect at the next decision.
type Stream struct {
	s         *sessionRef
	scope     authz.Scope
	peerFP    [32]byte
	peerKey   []byte
	grants    *authz.Store
	localID   *identity.Identity
	resource  string
	readBuf   []byte
	eof       bool
	writeDone bool
	closed    bool
}

// sessionRef wraps the session without exposing its internals to the façade's
// public API. It is assigned by establish().
type sessionRef struct {
	recordWriter func(byte, []byte) error
	recordReader func() (byte, []byte, error)
	zeroize      func()
}

func scopeFailure(op string) error {
	return spec.NewFailure(spec.ScopeViolation,
		"operation "+op+" is outside the authorized scope; operation denied", "")
}

// Read returns stream bytes; a graceful peer CLOSE is reported as io.EOF.
func (st *Stream) Read(p []byte) (int, error) {
	if st == nil || st.closed {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	if len(st.readBuf) == 0 {
		if st.eof {
			return 0, io.EOF
		}
		if st.localID.IsRevoked(st.peerKey) {
			return 0, spec.NewFailure(spec.Revoked, "peer key is on the local deny list; session terminated", "rotate the peer identity key, then start a new attempt")
		}
		if _, err := st.grants.Decide(st.peerFP, st.resource, "read"); err != nil {
			return 0, scopeFailure("read")
		}
		typ, plaintext, err := st.s.recordReader()
		if err != nil {
			return 0, err
		}
		switch typ {
		case spec.TypeData:
			st.readBuf = plaintext
		case spec.TypeClose:
			st.eof = true
			return 0, io.EOF
		default:
			return 0, errors.New("unexpected session record")
		}
	}
	n := copy(p, st.readBuf)
	st.readBuf = st.readBuf[n:]
	return n, nil
}

// Write sends application bytes as one protected DATA record.
func (st *Stream) Write(p []byte) (int, error) {
	if st == nil || st.closed || st.writeDone {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	if st.localID.IsRevoked(st.peerKey) {
		return 0, spec.NewFailure(spec.Revoked, "peer key is on the local deny list; session terminated", "rotate the peer identity key, then start a new attempt")
	}
	if _, err := st.grants.Decide(st.peerFP, st.resource, "write"); err != nil {
		return 0, scopeFailure("write")
	}
	if err := st.s.recordWriter(spec.TypeData, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// CloseWrite sends a graceful CLOSE record while keeping the read side open so
// a duplex peer can finish echoing buffered data.
func (st *Stream) CloseWrite() error {
	if st == nil || st.closed || st.writeDone {
		return nil
	}
	st.writeDone = true
	return st.s.recordWriter(spec.TypeClose, []byte(spec.Ended))
}

// Close sends CLOSE if needed, zeroizes session keys and closes the transport.
func (st *Stream) Close() error {
	if st == nil || st.closed {
		return nil
	}
	st.closed = true
	_ = st.CloseWrite()
	st.s.zeroize()
	return nil
}

// Scope returns the authority that authorized this stream.
func (st *Stream) Scope() authz.Scope { return st.scope }
