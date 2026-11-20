package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/IFindMe/open-upp/spec"
)

// fixedIdentity builds a deterministic identity from a zero seed so golden
// vectors are reproducible (ed25519.Sign is deterministic). Test-only.
func fixedIdentity(t *testing.T) *Identity {
	t.Helper()
	seed := make([]byte, 32)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	id := &Identity{
		Version:       FormatVersion,
		Suite:         SuiteEd25519,
		ClassHint:     "device",
		RootPublicKey: pub,
		KeyLog:        []KeyRecord{{PublicKey: pub}},
		privateKeys:   []ed25519.PrivateKey{priv},
	}
	st := statement{Version: FormatVersion, Kind: "self", Suite: SuiteEd25519, Subject: pub, ClassHint: "device"}
	id.SelfBinding = ed25519.Sign(priv, message(domainSelfBinding, canonical(st)))
	return id
}

// TestGoldenFingerprintVector pins the frozen fingerprint formula and tag bytes
// (protocol-v1.md §3.3, W7-AC4).
func TestGoldenFingerprintVector(t *testing.T) {
	id := fixedIdentity(t)
	const want = "31b58b19ec9a8a7ea15931cf099c9e93ede37318833fd9abeea11ea2f8aa1065"
	fp := id.Fingerprint()
	if got := hex.EncodeToString(fp[:]); got != want {
		t.Fatalf("fingerprint = %s, want golden %s", got, want)
	}
}

// TestGoldenPairwiseSNVector pins the full pairwise digest + 8-char grouping.
func TestGoldenPairwiseSNVector(t *testing.T) {
	var a, b [32]byte
	for i := range a {
		a[i] = byte(i)
		b[i] = byte(128 + i)
	}
	const digest = "2b05924959c3b5872831c19455b21297d0950c3cffb60097dba7667b63f27d96"
	pd := PairwiseSafetyDigest(a, b)
	if got := hex.EncodeToString(pd[:]); got != digest {
		t.Fatalf("pairwise digest = %s, want %s", got, digest)
	}
	const want = "FMCZESKZ YO2YOKBR YGKFLMQS S7IJKDB4 763ABF63 U5THWY7S PWLA"
	if got := PairwiseSafetyNumber(a, b); got != want {
		t.Fatalf("pairwise SN = %q, want %q", got, want)
	}
	if swapped := PairwiseSafetyNumber(b, a); swapped != want {
		t.Fatal("pairwise SN is not order-independent")
	}
}

func TestPairwiseSNFormat7Groups(t *testing.T) {
	id := mustCreate(t)
	other := mustCreate(t)
	sn := PairwiseSafetyNumber(id.Fingerprint(), other.Fingerprint())
	groups := strings.Split(sn, " ")
	if len(groups) != 7 {
		t.Fatalf("got %d groups, want 7", len(groups))
	}
	for i, g := range groups[:6] {
		if len(g) != 8 {
			t.Fatalf("group %d length %d, want 8", i, len(g))
		}
	}
	if len(groups[6]) != 4 {
		t.Fatalf("final group length %d, want 4", len(groups[6]))
	}
	if strings.ContainsAny(strings.ReplaceAll(sn, " ", ""), "0189") {
		t.Fatal("SN contains non-RFC4648 characters")
	}
	// Legacy single-identity display remains 13x4 and is a different value.
	if id.SafetyNumber() == sn {
		t.Fatal("legacy safety number must not equal pairwise SN")
	}
}

// TestPublicRecordRoundTripAndNoSecretLeak verifies Encoding/Decoding identity
// records and that local revocation/private keys are never transmitted.
func TestPublicRecordRoundTripAndNoSecretLeak(t *testing.T) {
	id := mustCreate(t)
	if err := id.Rotate(); err != nil {
		t.Fatal(err)
	}
	seed := hex.EncodeToString(id.privateKeys[0].Seed())
	pub := id.CurrentKey()
	if err := id.RevokeKey(pub); err != nil {
		t.Fatal(err)
	}
	rec, err := id.EncodePublicRecord()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rec, []byte(seed)) {
		t.Fatal("public record leaked a private key seed")
	}
	decoded, err := DecodePublicRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.privateKeys) != 0 || len(decoded.RevokedKeys) != 0 {
		t.Fatal("decoded public record carries private keys or local revocation list")
	}
	if err := decoded.Verify(); err != nil {
		t.Fatalf("decoded record failed Verify: %v", err)
	}
	if decoded.Fingerprint() != id.Fingerprint() {
		t.Fatal("fingerprint changed across record encode/decode")
	}
}

// TestPublicRecordTamperAndMalformed verifies that tampering with a signed
// continuity field and structural corruption are rejected by the decode/verify
// path used by the handshake (bad_proof).
func TestPublicRecordTamperAndMalformed(t *testing.T) {
	id := mustCreate(t)
	if err := id.Rotate(); err != nil {
		t.Fatal(err)
	}
	rec, err := id.EncodePublicRecord()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePublicRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	decoded.KeyLog[1].Continuity = bytes.Clone(decoded.KeyLog[1].Continuity)
	decoded.KeyLog[1].Continuity[0] ^= 0xff
	tampered, err := decoded.EncodePublicRecord()
	if err != nil {
		t.Fatal(err)
	}
	again, err := DecodePublicRecord(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Verify(); err == nil {
		t.Fatal("tampered continuity signature accepted after record decode")
	}

	// Truncation and a tampered key-log count are structural failures.
	for _, b := range [][]byte{rec[:len(rec)-1], rec[:8], {}} {
		if _, err := DecodePublicRecord(b); err == nil {
			t.Fatalf("malformed public record accepted: len=%d", len(b))
		}
	}
	// Rebuild the header with an absurd key-log count (field 5) via CANON-1.
	hdr := spec.DecodeFields(rec)
	parts := make([][]byte, 0, 6)
	for i := 0; i < 6; i++ {
		parts = append(parts, hdr.Next())
	}
	parts[5] = spec.U32(0xffff)
	badCount := spec.Canon(parts...)
	if _, err := DecodePublicRecord(badCount); err == nil {
		t.Fatal("out-of-range key count accepted")
	}
}

// TestVerifyChallengeRejectsReplayedAndForeignProof covers wrong-challenge and
// foreign-identity PoP rejection at the identity primitive (W7 area 2).
func TestVerifyChallengeRejectsReplayedAndForeignProof(t *testing.T) {
	a := mustCreate(t)
	b := mustCreate(t)
	sig, err := b.SignChallenge([]byte("challenge-one"))
	if err != nil {
		t.Fatal(err)
	}
	if !b.VerifyChallenge(b.CurrentKey(), []byte("challenge-one"), sig) {
		t.Fatal("valid PoP rejected")
	}
	if b.VerifyChallenge(b.CurrentKey(), []byte("challenge-two"), sig) {
		t.Fatal("PoP accepted for a different (replayed onto) challenge")
	}
	if a.VerifyChallenge(b.CurrentKey(), []byte("challenge-one"), sig) {
		t.Fatal("foreign identity proof accepted")
	}
	// A PoP whose signing key is not in the verifier's key log fails.
	if a.VerifyChallenge(a.CurrentKey(), []byte("challenge-one"), sig) {
		t.Fatal("PoP accepted under the wrong identity's key")
	}
}

// TestTagRegistryMatchesFrozenBytes guards against accidental tag drift.
func TestTagRegistryMatchesFrozenBytes(t *testing.T) {
	if spec.TagFingerprint != "open-upp/identity/fingerprint/v1" ||
		spec.TagSafetyNumber != "open-upp/identity/safety-number/v1" ||
		spec.TagHandshakePoP != "open-upp/handshake/pop/v1" {
		t.Fatal("frozen domain tag drifted")
	}
}
