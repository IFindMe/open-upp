package spec

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// U8/U32/U64 encode unsigned fixed-width big-endian integers for CANON-1.
func U8(n uint8) []byte { return []byte{n} }
func U32(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}
func U64(n uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, n)
	return b
}

// Canon encodes fields as the concatenation of u32_be len(field) || field in
// the given order. There are no maps and no optional fields; an absent value
// is an empty byte string (protocol-v1.md §3.1).
func Canon(fields ...[]byte) []byte {
	n := 4 * len(fields)
	for _, f := range fields {
		n += len(f)
	}
	out := make([]byte, 0, n)
	var size [4]byte
	for _, f := range fields {
		binary.BigEndian.PutUint32(size[:], uint32(len(f)))
		out = append(out, size[:]...)
		out = append(out, f...)
	}
	return out
}

// Fields decodes a CANON-1 blob in a fixed, caller-defined order.
type Fields struct {
	data []byte
	off  int
	err  error
}

func DecodeFields(b []byte) *Fields { return &Fields{data: b} }

// Next returns the next field bytes. It marks the decoder failed on a short or
// malformed input so subsequent calls also fail.
func (f *Fields) Next() []byte {
	if f.err != nil {
		return nil
	}
	if f.off+4 > len(f.data) {
		f.err = errors.New("short CANON field length")
		return nil
	}
	n := int(binary.BigEndian.Uint32(f.data[f.off : f.off+4]))
	f.off += 4
	if n < 0 || f.off+n > len(f.data) {
		f.err = errors.New("short CANON field body")
		return nil
	}
	out := f.data[f.off : f.off+n]
	f.off += n
	return out
}

// Done reports whether all fields were consumed with no decoding error.
func (f *Fields) Done() error {
	if f.err != nil {
		return f.err
	}
	if f.off != len(f.data) {
		return errors.New("trailing CANON bytes")
	}
	return nil
}

// EncodeFrame wraps a payload as u32_be payload_len || payload and rejects
// payloads above the frozen 64 KiB frame bound before they are written.
func EncodeFrame(payload []byte) ([]byte, error) {
	if len(payload) > MaxFrame {
		return nil, fmt.Errorf("frame payload %d exceeds %d", len(payload), MaxFrame)
	}
	out := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	return append(out, payload...), nil
}

// DecodeFrame reads one length-prefixed frame, rejecting oversize frames
// before allocating the payload.
func DecodeFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, fmt.Errorf("frame payload %d exceeds %d", n, MaxFrame)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// HKDF implements HKDF-SHA256 (extract followed by expand) using only stdlib.
func HKDFExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

// HKDFExpand expands prk into length bytes (at most 255*32).
func HKDFExpand(prk, info []byte, length int) ([]byte, error) {
	if length < 0 || length > 255*sha256.Size {
		return nil, errors.New("invalid HKDF output length")
	}
	out := make([]byte, 0, length)
	var block []byte
	var counter byte = 1
	for len(out) < length {
		h := hmac.New(sha256.New, prk)
		h.Write(block)
		h.Write(info)
		h.Write([]byte{counter})
		block = h.Sum(nil)
		out = append(out, block...)
		counter++
	}
	return out[:length], nil
}

func HKDF(salt, ikm, info []byte, length int) ([]byte, error) {
	prk := HKDFExtract(salt, ikm)
	return HKDFExpand(prk, info, length)
}
