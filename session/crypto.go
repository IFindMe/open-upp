package session

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"github.com/IFindMe/open-upp/spec"
)

// cipherState is one directional AES-256-GCM record stream with strict
// per-direction sequence numbers. The salt is direction-specific and the nonce
// is salt(4 bytes) || u64_be(seq); AAD binds the transcript hash, sequence,
// resource and operation (protocol-v1.md §5.3).
type cipherState struct {
	aead cipher.AEAD
	salt [4]byte
	seq  uint64
	key  []byte
}

func newCipherState(key, salt []byte) (*cipherState, error) {
	if len(key) != 32 || len(salt) != 4 {
		return nil, errors.New("invalid AEAD key or salt length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	cs := &cipherState{aead: aead, key: make([]byte, 32)}
	copy(cs.key, key)
	copy(cs.salt[:], salt)
	return cs, nil
}

func (c *cipherState) nonce(seq uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce[:4], c.salt[:])
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return nonce
}

func (c *cipherState) aad(th [32]byte, resource, op string, seq uint64) []byte {
	return spec.Canon(
		[]byte(spec.TagSessionData),
		th[:],
		spec.U64(seq),
		[]byte(resource),
		[]byte(op),
	)
}

// sealRecord returns CANON(u64_be seq, ciphertext) for the current sequence
// number and advances it. Ciphertext includes the GCM authentication tag.
func (c *cipherState) sealRecord(th [32]byte, resource, op string, plaintext []byte) ([]byte, error) {
	seq := c.seq
	ct := c.aead.Seal(nil, c.nonce(seq), plaintext, c.aad(th, resource, op, seq))
	c.seq++
	return spec.Canon(spec.U64(seq), ct), nil
}

// openRecord verifies the explicit sequence, decrypts, and advances. A low or
// out-of-order sequence or a failed GCM tag is a replay/terminal failure.
func (c *cipherState) openRecord(th [32]byte, resource, op string, fields []byte) ([]byte, error) {
	f := spec.DecodeFields(fields)
	seqBytes := f.Next()
	ct := f.Next()
	if err := f.Done(); err != nil {
		return nil, err
	}
	if len(seqBytes) != 8 {
		return nil, errors.New("invalid record sequence")
	}
	seq := binary.BigEndian.Uint64(seqBytes)
	if seq != c.seq {
		return nil, spec.NewFailure(spec.Replay, "duplicate or out-of-order session sequence number; session terminated", "restart; session keys were discarded and are not reused")
	}
	plaintext, err := c.aead.Open(nil, c.nonce(seq), ct, c.aad(th, resource, op, seq))
	if err != nil {
		return nil, spec.NewFailure(spec.Replay, "duplicate or out-of-order session sequence number; session terminated", "restart; session keys were discarded and are not reused")
	}
	c.seq++
	return plaintext, nil
}

func (c *cipherState) zeroize() {
	if c == nil {
		return
	}
	for i := range c.key {
		c.key[i] = 0
	}
	c.seq = 0
}
