package wire

import (
	"bytes"
	"errors"

	"github.com/IFindMe/open-upp/spec"
)

const (
	challengeSize = 32
	ephPubSize    = 32
	popSize       = 64
)

func versionFailure() error {
	return spec.NewFailure(spec.VersionRejected,
		"peer offered an unsupported version, suite or extension; no fallback attempted", "")
}

// BuildHello returns the exact HELLO payload: type || CANON(fields...).
func BuildHello(h Hello) ([]byte, error) {
	if h.Version != spec.Version {
		return nil, versionFailure()
	}
	if h.SuiteSet != spec.SuiteSet {
		return nil, versionFailure()
	}
	if len(h.Challenge) != challengeSize || len(h.EPHPub) != ephPubSize || len(h.Record) == 0 {
		return nil, errors.New("malformed hello fields")
	}
	fields := spec.Canon(
		spec.U8(h.Version),
		[]byte(h.SuiteSet),
		h.Challenge,
		h.EPHPub,
		h.Record,
	)
	return append([]byte{spec.TypeHello}, fields...), nil
}

// ParseHello decodes a HELLO payload and returns the exact received bytes so
// the caller can bind them into the transcript hash verbatim.
func ParseHello(payload []byte) (Hello, []byte, error) {
	var h Hello
	if len(payload) == 0 || payload[0] != spec.TypeHello {
		return h, nil, errors.New("not a hello frame")
	}
	raw := bytes.Clone(payload)
	f := spec.DecodeFields(payload[1:])
	v := f.Next()
	suite := f.Next()
	h.Challenge = f.Next()
	h.EPHPub = f.Next()
	h.Record = f.Next()
	if err := f.Done(); err != nil {
		return h, nil, err
	}
	if len(v) != 1 {
		return h, nil, errors.New("hello version field must be one byte")
	}
	h.Version = v[0]
	h.SuiteSet = string(suite)
	if h.Version != spec.Version || h.SuiteSet != spec.SuiteSet {
		return h, nil, versionFailure()
	}
	if len(h.Challenge) != challengeSize || len(h.EPHPub) != ephPubSize || len(h.Record) == 0 {
		return h, nil, errors.New("malformed hello fields")
	}
	return h, raw, nil
}

// BuildHelloResponse returns both the full payload and the exact prefix of it
// that omits the pop field. The prefix is what both sides hash into th.
func BuildHelloResponse(h HelloResponse) (payload, withoutPop []byte, err error) {
	if h.Version != spec.Version {
		return nil, nil, versionFailure()
	}
	if h.Suite != spec.Suite {
		return nil, nil, versionFailure()
	}
	if len(h.Challenge) != challengeSize || len(h.EPHPub) != ephPubSize || len(h.Record) == 0 || len(h.Pop) != popSize {
		return nil, nil, errors.New("malformed hello-response fields")
	}
	prefix := spec.Canon(
		spec.U8(h.Version),
		[]byte(h.Suite),
		h.Challenge,
		h.EPHPub,
		h.Record,
	)
	withoutPop = append([]byte{spec.TypeHelloResponse}, prefix...)
	full := append(append([]byte{}, withoutPop...), spec.Canon(h.Pop)...)
	return full, withoutPop, nil
}

// ParseHelloResponse decodes a HELLO_RESPONSE and returns the exact prefix of
// the payload before the pop field (the transcript-bound bytes).
func ParseHelloResponse(payload []byte) (HelloResponse, []byte, error) {
	var h HelloResponse
	if len(payload) == 0 || payload[0] != spec.TypeHelloResponse {
		return h, nil, errors.New("not a hello-response frame")
	}
	f := spec.DecodeFields(payload[1:])
	v := f.Next()
	suite := f.Next()
	h.Challenge = f.Next()
	h.EPHPub = f.Next()
	h.Record = f.Next()
	h.Pop = f.Next()
	if err := f.Done(); err != nil {
		return h, nil, err
	}
	if len(v) != 1 {
		return h, nil, errors.New("hello-response version field must be one byte")
	}
	h.Version = v[0]
	h.Suite = string(suite)
	if h.Version != spec.Version || h.Suite != spec.Suite {
		return h, nil, versionFailure()
	}
	if len(h.Challenge) != challengeSize || len(h.EPHPub) != ephPubSize || len(h.Record) == 0 || len(h.Pop) != popSize {
		return h, nil, errors.New("malformed hello-response fields")
	}
	// The prefix is the exact received byte sequence before the pop field's
	// length prefix. Done() above guarantees there are no trailing bytes, so
	// this slice is exactly the canonical prefix the responder signed.
	prefix := payload[:len(payload)-4-len(h.Pop)]
	return h, bytes.Clone(prefix), nil
}

// BuildHelloResponseWithoutPop reconstructs the canonical prefix of a
// HELLO_RESPONSE with the pop field omitted.
func BuildHelloResponseWithoutPop(h HelloResponse) ([]byte, error) {
	prefix := spec.Canon(
		spec.U8(h.Version),
		[]byte(h.Suite),
		h.Challenge,
		h.EPHPub,
		h.Record,
	)
	return append([]byte{spec.TypeHelloResponse}, prefix...), nil
}

// BuildFinished returns the FINISHED payload.
func BuildFinished(f Finished) ([]byte, error) {
	if len(f.Pop) != popSize {
		return nil, errors.New("malformed finished fields")
	}
	return append([]byte{spec.TypeFinished}, spec.Canon(f.Pop)...), nil
}

// ParseFinished decodes a FINISHED payload.
func ParseFinished(payload []byte) (Finished, error) {
	var f Finished
	if len(payload) == 0 || payload[0] != spec.TypeFinished {
		return f, errors.New("not a finished frame")
	}
	d := spec.DecodeFields(payload[1:])
	f.Pop = d.Next()
	if err := d.Done(); err != nil {
		return f, err
	}
	if len(f.Pop) != popSize {
		return f, errors.New("malformed finished fields")
	}
	return f, nil
}
