package discovery

// C5 discovery/hint tests (ADR-002 §3, §5). A tc... address is an opaque
// 0600 bearer locator: stored verbatim, shape-validated, never parsed into
// identity, pin or grant input, and never echoed in a diagnostic.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validFP = "abababababababababababababababababababababababababababababababab"

func rawHint(t *testing.T, fp, addr string, port uint16, transport string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"subject_fp": fp,
		"addr":       addr,
		"port":       port,
		"transport":  transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeRaw(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHintSave0600AndTailcatFieldsC5(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "peer.hint")
	const cap = "tcCAPABILITY-SAVED-VERBATIM-112233445566778899"
	var fp [32]byte
	for i := range fp {
		fp[i] = 0xab
	}
	if err := Save(p, Hint{SubjectFP: fp, Addr: cap, Port: 443, Transport: TransportTailcat}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("hint mode = %o, want 600", info.Mode().Perm())
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"transport": "tailcat"`) {
		t.Fatalf("hint missing tailcat discriminator: %s", raw)
	}
	if !strings.Contains(string(raw), cap) {
		t.Fatalf("hint did not store capability verbatim: %s", raw)
	}
	h, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if h.Addr != cap || h.Port != 443 || h.Transport != TransportTailcat || h.SubjectFP != fp {
		t.Fatalf("Load round-trip mismatch: %+v", h)
	}
}

func TestHintLoadRejectsMalformedC5(t *testing.T) {
	const secret = "LEDONOTECHO-9f3a"
	cases := []struct {
		name    string
		fp      string
		addr    string
		port    uint16
		trans   string
		want    string
		leakChk bool
	}{
		{"empty addr", validFP, "", 443, TransportTailcat, "address or port missing", false},
		{"zero port", validFP, "tc" + secret, 0, TransportTailcat, "address or port missing", true},
		{"invalid transport", validFP, "tc" + secret, 443, "udp", "transport is invalid", true},
		{"control char", validFP, "tc" + secret + "\ntrail", 443, TransportTailcat, "control character", true},
		{"oversized", validFP, "tc" + strings.Repeat("x", 8200) + secret, 443, TransportTailcat, "too long", true},
		{"missing tc prefix", validFP, "127.0.0.1" + secret, 443, TransportTailcat, "malformed", true},
		{"bad subject fp", "abcd", "tc" + secret, 443, TransportTailcat, "64 hex characters", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeRaw(t, t.TempDir(), "bad.hint", rawHint(t, tc.fp, tc.addr, tc.port, tc.trans))
			_, err := Load(p)
			if err == nil {
				t.Fatal("malformed hint unexpectedly loaded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.want)
			}
			if tc.leakChk && strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaked address: %q", err.Error())
			}
		})
	}
}

func TestResolverSubjectFPRoutingCheckC5(t *testing.T) {
	dir := t.TempDir()
	var expected [32]byte
	for i := range expected {
		expected[i] = 0xab
	}
	var other [32]byte
	for i := range other {
		other[i] = 0xcd
	}

	// Same expected fingerprint, two different opaque capabilities: routing
	// succeeds in both cases, proving the address is not the identity check.
	for i, cap := range []string{"tcCAP-ONE-0000", "tcCAP-TWO-9999"} {
		p := writeRaw(t, dir, "ok"+string(rune('a'+i))+".hint", rawHint(t, validFP, cap, 443, TransportTailcat))
		h, err := (Resolver{Path: p}).Resolve(expected)
		if err != nil {
			t.Fatalf("Resolve with capability %q: %v", cap, err)
		}
		if h.Addr != cap {
			t.Fatalf("resolved addr = %q, want %q", h.Addr, cap)
		}
	}

	p := writeRaw(t, dir, "mismatch.hint", rawHint(t, validFP, "tcCAP-ONE-0000", 443, TransportTailcat))
	if _, err := (Resolver{Path: p}).Resolve(other); err == nil {
		t.Fatal("Resolve accepted a mismatched subject fingerprint")
	} else if !strings.Contains(err.Error(), "does not match the expected peer") {
		t.Fatalf("unexpected mismatch error: %q", err.Error())
	}
}

func TestHintAddrNotDerivedIntoIdentityC5(t *testing.T) {
	// The SubjectFP is written by the identity owner, never derived from the
	// capability: two different capabilities with the same subject must yield
	// the exact same fingerprint bytes used by the identity/gate layers.
	dir := t.TempDir()
	p1 := writeRaw(t, dir, "h1", rawHint(t, validFP, "tcALPHA", 443, TransportTailcat))
	p2 := writeRaw(t, dir, "h2", rawHint(t, validFP, "tcBETA-DIFFERENT", 443, TransportTailcat))
	h1, e1 := Load(p1)
	h2, e2 := Load(p2)
	if e1 != nil || e2 != nil {
		t.Fatalf("Load errors: %v / %v", e1, e2)
	}
	if h1.SubjectFP != h2.SubjectFP {
		t.Fatal("fingerprint changed with the capability address")
	}
	if hexFP := strings.ToLower(stringify(h1.SubjectFP)); hexFP != validFP {
		t.Fatalf("fingerprint = %s, want %s", hexFP, validFP)
	}
}

// stringify renders the fingerprint as lowercase hex for the assertion above.
func stringify(fp [32]byte) string {
	const digits = "0123456789abcdef"
	var b strings.Builder
	for _, x := range fp {
		b.WriteByte(digits[x>>4])
		b.WriteByte(digits[x&0x0f])
	}
	return b.String()
}
