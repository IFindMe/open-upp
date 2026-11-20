// Package identity implements the local identity primitives proposed in
// docs/architecture/identity-and-key-lifecycle.md.
//
// This is a prototype for local identity creation, verification, rotation and
// revocation. It does not define a wire format, handshake, discovery mechanism
// or authorization policy. The canonical encoding below is an internal,
// deterministic local-storage format only.
package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	// FormatVersion is the version of the local identity record.
	FormatVersion = 1
	// SuiteEd25519 is the only suite implemented by this prototype.
	SuiteEd25519 = "Ed25519"

	domainFingerprint       = "open-upp/identity/fingerprint/v1"
	domainKeyFingerprint    = "open-upp/identity/key-fingerprint/v1"
	domainSelfBinding       = "open-upp/identity/self-bind/v1"
	domainContinuity        = "open-upp/identity/continuity/v1"
	domainAcknowledgment    = "open-upp/identity/acknowledgment/v1"
	domainProofOfPossession = "open-upp/identity/pop/v1"
)

// statement is the deterministic structure signed by identity keys. Field
// order is fixed by the struct; no maps are used, so encoding/json emits a
// single canonical byte sequence for a given statement.
type statement struct {
	Version     int    `json:"version"`
	Kind        string `json:"kind"`
	Suite       string `json:"suite"`
	Subject     []byte `json:"subject"`
	Predecessor []byte `json:"predecessor,omitempty"`
	ClassHint   string `json:"class_hint,omitempty"`
}

// KeyRecord is one entry in an identity's append-only key log.
type KeyRecord struct {
	PublicKey      ed25519.PublicKey
	Continuity     []byte // predecessor signs the successor key
	Acknowledgment []byte // successor acknowledges the link
}

// Identity is a local, key-bound identity record.
type Identity struct {
	Version       int
	Suite         string
	ClassHint     string
	RootPublicKey ed25519.PublicKey
	SelfBinding   []byte
	KeyLog        []KeyRecord
	RevokedKeys   [][]byte

	privateKeys []ed25519.PrivateKey
}

// Create generates a new Ed25519 root key and self-binding statement. No
// registration, name, address or authorization grant is created.
func Create(classHint string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}
	id := &Identity{
		Version:       FormatVersion,
		Suite:         SuiteEd25519,
		ClassHint:     classHint,
		RootPublicKey: pub,
		KeyLog:        []KeyRecord{{PublicKey: pub}},
		privateKeys:   []ed25519.PrivateKey{priv},
	}
	st := statement{
		Version:   FormatVersion,
		Kind:      "self",
		Suite:     SuiteEd25519,
		Subject:   pub,
		ClassHint: classHint,
	}
	id.SelfBinding = ed25519.Sign(priv, message(domainSelfBinding, canonical(st)))
	return id, nil
}

// Verify checks the self-binding statement and every continuity link.
func (id *Identity) Verify() error {
	if id == nil {
		return errors.New("nil identity")
	}
	if id.Version != FormatVersion {
		return fmt.Errorf("unsupported format version %d", id.Version)
	}
	if id.Suite != SuiteEd25519 {
		return fmt.Errorf("unsupported suite %q", id.Suite)
	}
	if len(id.RootPublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid root public key length")
	}
	if len(id.KeyLog) == 0 {
		return errors.New("empty key log")
	}
	if !bytes.Equal(id.KeyLog[0].PublicKey, id.RootPublicKey) {
		return errors.New("key log does not start at root key")
	}

	self := statement{
		Version:   id.Version,
		Kind:      "self",
		Suite:     id.Suite,
		Subject:   id.RootPublicKey,
		ClassHint: id.ClassHint,
	}
	if !ed25519.Verify(id.RootPublicKey, message(domainSelfBinding, canonical(self)), id.SelfBinding) {
		return errors.New("invalid self-binding signature")
	}

	for i := 1; i < len(id.KeyLog); i++ {
		prev := id.KeyLog[i-1].PublicKey
		cur := id.KeyLog[i].PublicKey
		if len(cur) != ed25519.PublicKeySize {
			return fmt.Errorf("key log entry %d has invalid length", i)
		}
		cont := statement{Version: id.Version, Kind: "continuity", Suite: id.Suite, Subject: cur, Predecessor: prev}
		if !ed25519.Verify(prev, message(domainContinuity, canonical(cont)), id.KeyLog[i].Continuity) {
			return fmt.Errorf("invalid continuity signature at key %d", i)
		}
		ack := statement{Version: id.Version, Kind: "acknowledgment", Suite: id.Suite, Subject: cur, Predecessor: prev}
		if !ed25519.Verify(cur, message(domainAcknowledgment, canonical(ack)), id.KeyLog[i].Acknowledgment) {
			return fmt.Errorf("invalid acknowledgment signature at key %d", i)
		}
	}
	// Local revocation is a deny decision, not a structural validity failure:
	// a revoked key must remain parseable/loadable so it can be rotated away
	// from. SignChallenge and VerifyChallenge enforce the deny decision.
	return nil
}

// Fingerprint returns SHA-256(domain || suite || root public key). It is stable
// across routine key rotation and independent of location or transport.
func (id *Identity) Fingerprint() [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(domainFingerprint))
	h.Write([]byte{0})
	h.Write([]byte(id.Suite))
	h.Write([]byte{0})
	h.Write(id.RootPublicKey)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// KeyFingerprint identifies the current key in the log, not the identity.
func (id *Identity) KeyFingerprint() [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(domainKeyFingerprint))
	h.Write([]byte{0})
	h.Write([]byte(id.Suite))
	h.Write([]byte{0})
	h.Write(id.CurrentKey())
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SafetyNumber renders this identity's own fingerprint as unpadded RFC 4648
// base32 in groups of four characters. The base32 alphabet contains no 0, 1, 8
// or 9. This is a display form of a single identity's fingerprint, not the
// pairwise safety number described in the design doc.
func (id *Identity) SafetyNumber() string {
	sum := id.Fingerprint()
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		end := i + 4
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
	}
	return b.String()
}

// CurrentKey returns a copy of the most recent key in the log.
func (id *Identity) CurrentKey() ed25519.PublicKey {
	if id == nil || len(id.KeyLog) == 0 {
		return nil
	}
	return bytes.Clone(id.KeyLog[len(id.KeyLog)-1].PublicKey)
}

// SignChallenge proves possession of the current private key over a fresh
// challenge. The identity key is sign-only and never derives session material.
// A locally revoked current key is refused so no unusable signature is emitted.
func (id *Identity) SignChallenge(challenge []byte) ([]byte, error) {
	if len(challenge) == 0 {
		return nil, errors.New("empty challenge")
	}
	if len(id.privateKeys) == 0 {
		return nil, errors.New("no private key available")
	}
	current := id.CurrentKey()
	if id.IsRevoked(current) {
		return nil, errors.New("current key is locally revoked")
	}
	priv := id.privateKeys[len(id.privateKeys)-1]
	return ed25519.Sign(priv, message(domainProofOfPossession, current, challenge)), nil
}

// VerifyChallenge checks a proof of possession from a key in this identity's
// key log, rejects locally revoked keys, and does not grant authorization.
func (id *Identity) VerifyChallenge(pub ed25519.PublicKey, challenge, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(challenge) == 0 || len(sig) != ed25519.SignatureSize {
		return false
	}
	// Bind the proof to this identity: a signature by another identity's key
	// must not verify as a proof for this identity.
	member := false
	for _, rec := range id.KeyLog {
		if bytes.Equal(rec.PublicKey, pub) {
			member = true
			break
		}
	}
	if !member || id.IsRevoked(pub) {
		return false
	}
	msg := message(domainProofOfPossession, pub, challenge)
	return ed25519.Verify(pub, msg, sig)
}

// Rotate appends a successor key with both a continuity proof from the current
// key and an acknowledgment from the successor. The fingerprint does not change.
func (id *Identity) Rotate() error {
	if len(id.privateKeys) != len(id.KeyLog) {
		return errors.New("cannot rotate: private keys unavailable")
	}
	prevPub := id.CurrentKey()
	prevPriv := id.privateKeys[len(id.privateKeys)-1]
	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate successor key: %w", err)
	}

	cont := statement{Version: id.Version, Kind: "continuity", Suite: id.Suite, Subject: newPub, Predecessor: prevPub}
	ack := statement{Version: id.Version, Kind: "acknowledgment", Suite: id.Suite, Subject: newPub, Predecessor: prevPub}
	record := KeyRecord{
		PublicKey:      newPub,
		Continuity:     ed25519.Sign(prevPriv, message(domainContinuity, canonical(cont))),
		Acknowledgment: ed25519.Sign(newPriv, message(domainAcknowledgment, canonical(ack))),
	}
	id.KeyLog = append(id.KeyLog, record)
	id.privateKeys = append(id.privateKeys, newPriv)
	return id.Verify()
}

// RevokeKey adds a key to the local deny list. Propagation is out of scope.
func (id *Identity) RevokeKey(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid public key length")
	}
	for _, revoked := range id.RevokedKeys {
		if bytes.Equal(revoked, pub) {
			return nil
		}
	}
	id.RevokedKeys = append(id.RevokedKeys, bytes.Clone(pub))
	return nil
}

// IsRevoked reports whether a key is on the local deny list.
func (id *Identity) IsRevoked(pub ed25519.PublicKey) bool {
	for _, revoked := range id.RevokedKeys {
		if bytes.Equal(revoked, pub) {
			return true
		}
	}
	return false
}

// Display returns non-secret information suitable for terminal output.
func (id *Identity) Display() string {
	class := id.ClassHint
	if class == "" {
		class = "(none)"
	}
	return strings.Join([]string{
		"suite:         " + id.Suite,
		"class hint:    " + class,
		"fingerprint:   " + fmt.Sprintf("%x", id.Fingerprint()),
		"safety number: " + id.SafetyNumber(),
		"current key:   " + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id.CurrentKey()),
		"keys in log:   " + fmt.Sprintf("%d", len(id.KeyLog)),
		"revoked keys:  " + fmt.Sprintf("%d", len(id.RevokedKeys)),
	}, "\n")
}

func message(domain string, parts ...[]byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(domain)
	buf.WriteByte(0)
	var size [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		buf.Write(size[:])
		buf.Write(part)
	}
	return buf.Bytes()
}

func canonical(st statement) []byte {
	b, err := json.Marshal(st)
	if err != nil {
		panic("identity: canonical statement encoding failed: " + err.Error())
	}
	return b
}
