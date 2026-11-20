package verify

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fp(fill byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = fill
	}
	return out
}

func TestFormatParseAndEqualFullDigest(t *testing.T) {
	d := fp(0x7a)
	s := Format(d)
	groups := strings.Split(s, " ")
	if len(groups) != 7 || len(groups[6]) != 4 {
		t.Fatalf("bad SN grouping: %q", s)
	}
	parsed, err := ParseSN(s)
	if err != nil || parsed != d {
		t.Fatalf("ParseSN(Format(d)) = %x, err %v", parsed, err)
	}
	// Spaces stripped and case folded, as the CLI promises.
	lower := strings.ToLower(strings.ReplaceAll(s, " ", ""))
	parsed2, err := ParseSN(lower)
	if err != nil || parsed2 != d {
		t.Fatalf("ParseSN(normalized) = %x, err %v", parsed2, err)
	}
	if !Equal(d, parsed) {
		t.Fatal("Equal rejected identical digests")
	}
	other := d
	other[0] ^= 0xff
	if Equal(d, other) {
		t.Fatal("Equal accepted different digests")
	}

	// Legacy 4-char code and wrong length are usage errors, never a match.
	for _, bad := range []string{"ABCD EFGH", "ABCD", strings.Repeat("A", 51), strings.Repeat("A", 53)} {
		if _, err := ParseSN(bad); err == nil {
			t.Fatalf("ParseSN accepted %q", bad)
		}
	}
	// 52 chars of invalid base32 rejected.
	if _, err := ParseSN(strings.Repeat("0", 52)); err == nil {
		t.Fatal("ParseSN accepted non-base32 characters")
	}
}

func TestDigestOrderIndependent(t *testing.T) {
	a, b := fp(0x01), fp(0x02)
	if Digest(a, b) != Digest(b, a) {
		t.Fatal("pairwise digest is order-dependent")
	}
}

func TestPinChangeDetectionAndNoDegradedSurface(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.json")
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	idFP := fp(0x10)
	keyA := bytes.Repeat([]byte{0xaa}, 32)
	digest := fp(0x20)

	if got := store.Check(idFP, keyA); got != ChangeFirst {
		t.Fatalf("first contact change = %d, want ChangeFirst", got)
	}
	if err := store.Commit(idFP, keyA, digest); err != nil {
		t.Fatal(err)
	}
	if got := store.Check(idFP, keyA); got != ChangeNone {
		t.Fatalf("reuse change = %d, want ChangeNone", got)
	}
	keyB := bytes.Repeat([]byte{0xbb}, 32)
	if got := store.Check(idFP, keyB); got != ChangeKey {
		t.Fatalf("rotated key change = %d, want ChangeKey", got)
	}
	if got := store.Check(fp(0x11), keyA); got != ChangeRoot {
		t.Fatalf("root change = %d, want ChangeRoot", got)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Check(idFP, keyA); got != ChangeNone {
		t.Fatalf("pin not persisted: change = %d", got)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("pin file mode = %o, want 600", info.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(strings.ToLower(string(data)), "degrad") || strings.Contains(strings.ToLower(string(data)), "tofu") {
		t.Fatalf("pin file contains TOFU/degraded state: %s", data)
	}

	// Structural guard: Pin has no Degraded/TOFU field in v1 (W5c).
	typ := reflect.TypeOf(Pin{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		if strings.Contains(name, "degrad") || strings.Contains(name, "tofu") {
			t.Fatalf("Pin exposes TOFU surface: %s", typ.Field(i).Name)
		}
	}
	if typ.NumField() != 3 {
		t.Fatalf("Pin field count = %d, want 3", typ.NumField())
	}
}
