package authz

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/IFindMe/open-upp/identity"
	"github.com/IFindMe/open-upp/spec"
)

func newAuthority(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Create("device")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func subjectFP(fill byte) [32]byte {
	var fp [32]byte
	for i := range fp {
		fp[i] = fill
	}
	return fp
}

func storeWith(t *testing.T, g Grant) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "grants.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(g); err != nil {
		t.Fatalf("Add: %v", err)
	}
	return s, path
}

// TestDecideIsSoleGrantPathAndScopeEnforced covers valid scope and every
// mismatch dimension. The fingerprint is a lookup key only.
func TestDecideIsSoleGrantPathAndScopeEnforced(t *testing.T) {
	authority := newAuthority(t)
	subject := subjectFP(0x11)
	g, err := NewGrant(authority, subject, "stream", []string{"open", "read", "write"})
	if err != nil {
		t.Fatal(err)
	}
	s, path := storeWith(t, *g)

	scope, err := s.Decide(subject, "stream", "write")
	if err != nil {
		t.Fatalf("authorized Decide: %v", err)
	}
	if scope.GrantID != g.ID || scope.Resource != "stream" || len(scope.Ops) != 3 {
		t.Fatalf("unexpected scope: %+v", scope)
	}

	// Wrong op / resource / subject all deny.
	if _, err := s.Decide(subject, "stream", "admin"); !errors.Is(err, ErrDenied) {
		t.Fatalf("out-of-scope op not denied: %v", err)
	}
	if _, err := s.Decide(subject, "other", "open"); !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong resource not denied: %v", err)
	}
	if _, err := s.Decide(subjectFP(0x22), "stream", "open"); !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong subject fp not denied: %v", err)
	}

	// Persisted store enforces the same decisions (verification state irrelevant).
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.Decide(subject, "stream", "open"); err != nil {
		t.Fatalf("persisted grant not honored: %v", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("grant file mode = %o, want 600", info.Mode().Perm())
	}
}

// TestInvalidAndTamperedGrantsRejected verifies grant authenticity. Mutating
// any signed field or the signature/certificate key breaks Verify and Decide.
func TestInvalidAndTamperedGrantsRejected(t *testing.T) {
	authority := newAuthority(t)
	subject := subjectFP(0x33)
	base, err := NewGrant(authority, subject, "stream", []string{"open", "read"})
	if err != nil {
		t.Fatal(err)
	}
	if !base.Verify() {
		t.Fatal("freshly signed grant does not verify")
	}

	mutations := map[string]func(*Grant){
		"ops":      func(g *Grant) { g.Ops = append(g.Ops, "write") },
		"resource": func(g *Grant) { g.Resource = "admin" },
		"subject": func(g *Grant) {
			other := subjectFP(0x44)
			g.SubjectFP = hex.EncodeToString(other[:])
		},
		"signature": func(g *Grant) {
			b, _ := hex.DecodeString(g.Signature)
			b[0] ^= 0xff
			g.Signature = hex.EncodeToString(b)
		},
		"authority key": func(g *Grant) {
			g.AuthorityKey = hex.EncodeToString(newAuthority(t).CurrentKey())
		},
		"version": func(g *Grant) { g.Version = 2 },
	}
	for name, mutate := range mutations {
		g := *base
		g.Ops = append([]string(nil), base.Ops...)
		mutate(&g)
		if g.Verify() {
			t.Fatalf("tampered %s grant still verifies", name)
		}
		s, _ := Load(filepath.Join(t.TempDir(), "grants.json"))
		s.grants = []Grant{g} // store holds only the tampered grant
		if _, err := s.Decide(subject, "stream", "open"); !errors.Is(err, ErrDenied) {
			t.Fatalf("tampered %s grant was not denied: %v", name, err)
		}
	}
	// Store.Add refuses an invalid grant outright.
	bad := *base
	bad.Resource = "admin"
	s, _ := storeWith(t, *base)
	if err := s.Add(bad); err == nil {
		t.Fatal("Store.Add accepted an invalid grant")
	}
}

// TestRevokeAndGrantBound cover local revocation (effective at next decision)
// and the frozen 1024-grant bound.
func TestRevokeAndGrantBound(t *testing.T) {
	authority := newAuthority(t)
	subject := subjectFP(0x55)
	g, _ := NewGrant(authority, subject, "stream", []string{"open", "read", "write"})
	s, path := storeWith(t, *g)

	if _, err := s.Decide(subject, "stream", "open"); err != nil {
		t.Fatalf("pre-revoke decision: %v", err)
	}
	if err := s.Revoke(g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decide(subject, "stream", "open"); !errors.Is(err, ErrDenied) {
		t.Fatalf("revoked grant still authorizes: %v", err)
	}
	reloaded, _ := Load(path)
	if _, err := reloaded.Decide(subject, "stream", "open"); !errors.Is(err, ErrDenied) {
		t.Fatal("revocation did not survive reload")
	}
	if err := s.Revoke("does-not-exist"); err == nil {
		t.Fatal("revoking unknown grant succeeded")
	}

	bound, _ := Load(filepath.Join(t.TempDir(), "bound.json"))
	bound.grants = make([]Grant, spec.MaxGrants)
	if err := bound.Add(*g); err == nil {
		t.Fatal("grant bound not enforced")
	}
}

// TestRevokedAuthorityCannotIssueGrant covers revoked/rotated signing key
// rejection at issuance: SignChallenge refuses a locally revoked current key.
func TestRevokedAuthorityCannotIssueGrant(t *testing.T) {
	authority := newAuthority(t)
	if err := authority.RevokeKey(authority.CurrentKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGrant(authority, subjectFP(0x66), "stream", []string{"open"}); err == nil {
		t.Fatal("revoked authority key issued a grant")
	}
	// After rotating away from the revoked key, issuance works again.
	if err := authority.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGrant(authority, subjectFP(0x66), "stream", []string{"open"}); err != nil {
		t.Fatalf("issuance after recovery failed: %v", err)
	}
}
