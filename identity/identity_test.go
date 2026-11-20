package identity

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustCreate(t *testing.T) *Identity {
	t.Helper()
	id, err := Create("device")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return id
}

func TestFingerprintStableAcrossRotation(t *testing.T) {
	id := mustCreate(t)
	before := id.Fingerprint()
	firstKey := id.CurrentKey()

	if err := id.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if id.Fingerprint() != before {
		t.Fatal("fingerprint changed on routine rotation")
	}
	if bytes.Equal(id.CurrentKey(), firstKey) {
		t.Fatal("current key did not change")
	}
	if err := id.Verify(); err != nil {
		t.Fatalf("Verify after rotation: %v", err)
	}
}

func TestDifferentRootsHaveDifferentFingerprints(t *testing.T) {
	a := mustCreate(t)
	b := mustCreate(t)
	if a.Fingerprint() == b.Fingerprint() {
		t.Fatal("two independently generated roots collided")
	}
}

func TestProofOfPossession(t *testing.T) {
	id := mustCreate(t)
	challenge := []byte("fresh-challenge-42")
	sig, err := id.SignChallenge(challenge)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}
	if !id.VerifyChallenge(id.CurrentKey(), challenge, sig) {
		t.Fatal("valid proof rejected")
	}
	if id.VerifyChallenge(id.CurrentKey(), []byte("different"), sig) {
		t.Fatal("proof accepted for a different challenge")
	}
	other := mustCreate(t)
	if id.VerifyChallenge(other.CurrentKey(), challenge, sig) {
		t.Fatal("proof accepted under a substituted key")
	}
	if _, err := id.SignChallenge(nil); err == nil {
		t.Fatal("empty challenge accepted")
	}
}

func TestContinuityChainTamperingDetected(t *testing.T) {
	id := mustCreate(t)
	if err := id.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := id.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	id.KeyLog[1].Continuity = bytes.Clone(id.KeyLog[1].Continuity)
	id.KeyLog[1].Continuity[0] ^= 0xff
	if err := id.Verify(); err == nil {
		t.Fatal("tampered continuity signature accepted")
	}
}

func TestSafetyNumberUsesRFC4648Alphabet(t *testing.T) {
	s := mustCreate(t).SafetyNumber()
	groups := strings.Split(s, " ")
	if len(groups) != 13 {
		t.Fatalf("got %d groups, want 13", len(groups))
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	for _, r := range strings.ReplaceAll(s, " ", "") {
		if !strings.ContainsRune(alphabet, r) {
			t.Fatalf("invalid base32 character %q in safety number", r)
		}
	}
}

func TestStorageRoundTripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	id := mustCreate(t)
	if err := id.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := Save(path, id); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity file mode = %o, want 600", info.Mode().Perm())
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Fingerprint() != id.Fingerprint() {
		t.Fatal("fingerprint changed across storage round trip")
	}
	challenge := []byte("challenge-after-restart")
	sig, err := loaded.SignChallenge(challenge)
	if err != nil {
		t.Fatalf("SignChallenge after load: %v", err)
	}
	if !loaded.VerifyChallenge(loaded.CurrentKey(), challenge, sig) {
		t.Fatal("proof from loaded identity rejected")
	}
}

func TestDisplayDoesNotLeakPrivateKey(t *testing.T) {
	id := mustCreate(t)
	seed := base64.StdEncoding.EncodeToString(id.privateKeys[0].Seed())
	if strings.Contains(id.Display(), seed) {
		t.Fatal("Display leaked a private key seed")
	}
}

func TestRevokedKeyCannotProvePossession(t *testing.T) {
	id := mustCreate(t)
	pub := id.CurrentKey()
	challenge := []byte("challenge")
	sig, err := id.SignChallenge(challenge)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}
	if err := id.RevokeKey(pub); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if id.VerifyChallenge(pub, challenge, sig) {
		t.Fatal("revoked key still accepted for proof of possession")
	}
}

func TestSaveOverExistingFileEnforces0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("create existing file: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod existing file: %v", err)
	}
	id := mustCreate(t)
	if err := Save(path, id); err != nil {
		t.Fatalf("Save over existing file: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("identity file mode after overwrite = %o, want 600", got)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load after overwrite: %v", err)
	}
}

func TestRevokedKeyStillLoadsAndCanRotate(t *testing.T) {
	id := mustCreate(t)
	if err := id.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	revoked := id.CurrentKey()
	if err := id.RevokeKey(revoked); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if err := id.Verify(); err != nil {
		t.Fatalf("Verify with revoked key: %v", err)
	}
	data, err := id.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := Parse(data); err != nil {
		t.Fatalf("Parse with revoked key: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	if err := Save(path, id); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load with revoked key: %v", err)
	}
	if !loaded.IsRevoked(revoked) {
		t.Fatal("revocation did not survive the storage round trip")
	}
	before := loaded.Fingerprint()
	if err := loaded.Rotate(); err != nil {
		t.Fatalf("Rotate after Load with revoked key: %v", err)
	}
	if loaded.Fingerprint() != before {
		t.Fatal("fingerprint changed on rotation after revocation")
	}
	if _, err := loaded.SignChallenge([]byte("after-recovery")); err != nil {
		t.Fatalf("SignChallenge after rotating away from revoked key: %v", err)
	}
}

func TestVerifyChallengeRejectsForeignIdentityKey(t *testing.T) {
	a := mustCreate(t)
	b := mustCreate(t)
	challenge := []byte("shared-challenge")
	sig, err := b.SignChallenge(challenge)
	if err != nil {
		t.Fatalf("b.SignChallenge: %v", err)
	}
	if a.VerifyChallenge(b.CurrentKey(), challenge, sig) {
		t.Fatal("proof from a foreign identity key was accepted")
	}
	if !b.VerifyChallenge(b.CurrentKey(), challenge, sig) {
		t.Fatal("sanity check: b's own valid proof was rejected")
	}
}

func TestSignChallengeRejectsRevokedCurrentKey(t *testing.T) {
	id := mustCreate(t)
	if err := id.RevokeKey(id.CurrentKey()); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if _, err := id.SignChallenge([]byte("challenge")); err == nil {
		t.Fatal("SignChallenge succeeded with a locally revoked current key")
	}
}
