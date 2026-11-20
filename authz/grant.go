// Package authz implements the local, signed, scoped grant model (W3 D6,
// protocol-v1.md §7). A fingerprint is only a lookup key: verification,
// possession, hint acceptance and transport success never imply authority.
package authz

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/IFindMe/open-upp/identity"
	"github.com/IFindMe/open-upp/spec"
)

// Grant is a local scoped authority object. It is not sent over the wire.
type Grant struct {
	Version      uint8    `json:"version"`
	ID           string   `json:"grant_id"`   // 32 hex chars (16 random bytes)
	SubjectFP    string   `json:"subject_fp"` // full 64-hex fingerprint
	Resource     string   `json:"resource"`
	Ops          []string `json:"ops"`
	Enabled      bool     `json:"enabled"`
	AuthorityKey string   `json:"authority_key"` // hex of granting identity's current key
	Signature    string   `json:"signature"`     // hex of SignChallenge over signedBlob
}

// signedBlob is the CANON-1 object signed under open-upp/grant/v1. ops is a
// length-prefixed list because CANON-1 has no array type.
func signedBlob(g Grant) ([]byte, error) {
	id, err := hex.DecodeString(g.ID)
	if err != nil || len(id) != 16 {
		return nil, errors.New("grant id must be 16 random bytes")
	}
	fp, err := hex.DecodeString(g.SubjectFP)
	if err != nil || len(fp) != 32 {
		return nil, errors.New("grant subject fingerprint must be 32 bytes")
	}
	ops := make([][]byte, 0, len(g.Ops)+1)
	ops = append(ops, spec.U32(uint32(len(g.Ops))))
	for _, op := range g.Ops {
		ops = append(ops, []byte(op))
	}
	fields := [][]byte{
		[]byte(spec.TagGrant),
		spec.U8(g.Version),
		id,
		fp,
		[]byte(g.Resource),
	}
	fields = append(fields, ops...)
	// `enabled` is local revocation state, not a signed issuance field: W4's
	// `grant revoke` takes no signing identity, so a revoke sets enabled=false
	// without invalidating the grant's authenticity check. A disabled grant is
	// skipped by Decide regardless.
	return spec.Canon(fields...), nil
}

// NewGrant creates and signs a grant using the granting identity's current
// key. It requires an explicit operator consent decision before being called.
func NewGrant(authority *identity.Identity, subjectFP [32]byte, resource string, ops []string) (*Grant, error) {
	if authority == nil || len(ops) == 0 {
		return nil, errors.New("grant requires an authority and at least one op")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("generate grant id: %w", err)
	}
	g := &Grant{
		Version:      spec.Version,
		ID:           hex.EncodeToString(id[:]),
		SubjectFP:    hex.EncodeToString(subjectFP[:]),
		Resource:     resource,
		Ops:          append([]string(nil), ops...),
		Enabled:      true,
		AuthorityKey: hex.EncodeToString(authority.CurrentKey()),
	}
	blob, err := signedBlob(*g)
	if err != nil {
		return nil, err
	}
	sig, err := authority.SignChallenge(blob)
	if err != nil {
		return nil, fmt.Errorf("sign grant: %w", err)
	}
	g.Signature = hex.EncodeToString(sig)
	return g, nil
}

// Verify checks grant authenticity under the recorded authority key.
func (g Grant) Verify() bool {
	blob, err := signedBlob(g)
	if err != nil {
		return false
	}
	pub, err := hex.DecodeString(g.AuthorityKey)
	if err != nil || len(pub) != 32 {
		return false
	}
	sig, err := hex.DecodeString(g.Signature)
	if err != nil || len(sig) != 64 {
		return false
	}
	return identity.VerifySignature(pub, blob, sig)
}
