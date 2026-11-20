package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IFindMe/open-upp/identity"
)

var cliBin string

// TestMain builds the real upp binary once so subprocess tests exercise actual
// exit codes and stderr rendering (os.Exit cannot be intercepted in-process).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "upp-cli-w7-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cliBin = filepath.Join(dir, "upp")
	cmd := exec.Command("go", "build", "-o", cliBin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build upp: %v\n%s\n", err, out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(cliBin, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run upp: %v", err)
		}
		code = ee.ExitCode()
	}
	return code, out.String(), errOut.String()
}

func saveTestIdentity(t *testing.T, dir, name string) (*identity.Identity, string) {
	t.Helper()
	id, err := identity.Create("device")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := identity.Save(path, id); err != nil {
		t.Fatal(err)
	}
	return id, path
}

func assertLine(t *testing.T, s, line string) {
	t.Helper()
	for _, got := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if got == line {
			return
		}
	}
	t.Fatalf("missing exact line %q in:\n%s", line, s)
}

// TestHelpAndNoTOFUSurface: help exits 0 and exposes no TOFU/allow-from flag.
func TestHelpAndNoTOFUSurface(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		code, out, _ := runCLI(t, "", arg)
		if code != 0 {
			t.Fatalf("upp %s exit = %d", arg, code)
		}
		low := strings.ToLower(out)
		if strings.Contains(low, "tofu") || strings.Contains(low, "allow-from") || strings.Contains(low, "pin-reuse") {
			t.Fatalf("upp %s exposes TOFU/bypass flag:\n%s", arg, out)
		}
	}
}

// TestAllowToFUFlagRejected verifies the W6 negative check: the flag simply
// does not exist and parsing yields the frozen usage error with exit 2.
func TestAllowToFUFlagRejected(t *testing.T) {
	code, _, errOut := runCLI(t, "", "connect", "-allow-tofu")
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stderr:\n%s", code, errOut)
	}
	assertLine(t, errOut, `upp: usage error: flag provided but not defined: -allow-tofu; run "upp help"`)
}

func TestUsageExitCodesAndStrings(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no command", nil, ""},
		{"unknown command", []string{"bogus"}, ""},
		{"verify missing peer", []string{"verify"}, `upp: usage error: -peer is required and no extra arguments are accepted; run "upp help"`},
		{"grant missing subcommand", []string{"grant"}, `upp: usage error: grant requires add, revoke or list; run "upp help"`},
		{"grant unknown subcommand", []string{"grant", "bogus"}, `upp: usage error: unknown grant subcommand "bogus"; run "upp help"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut := runCLI(t, "", tc.args...)
			if code != 2 {
				t.Fatalf("exit = %d, want 2; stderr:\n%s", code, errOut)
			}
			if tc.want != "" {
				assertLine(t, errOut, tc.want)
			}
		})
	}
}

// TestVerifyCommandExactStrings covers the pairwise SN display and both
// mismatch paths with exact W4 strings and exit codes.
func TestVerifyCommandExactStrings(t *testing.T) {
	dir := t.TempDir()
	_, aPath := saveTestIdentity(t, dir, "alice.json")
	_, bPath := saveTestIdentity(t, dir, "bob.json")
	alice, _ := identity.Load(aPath)
	bob, _ := identity.Load(bPath)
	afp, bfp := alice.Fingerprint(), bob.Fingerprint()
	sn := identity.PairwiseSafetyNumber(afp, bfp)

	code, out, errOut := runCLI(t, "", "verify", "-identity", aPath, "-peer", bPath)
	if code != 0 || errOut != "" {
		t.Fatalf("verify exit %d stderr %q", code, errOut)
	}
	assertLine(t, out, fmt.Sprintf("upp: local fingerprint: %x", afp))
	assertLine(t, out, fmt.Sprintf("upp: peer  fingerprint: %x", bfp))
	assertLine(t, out, "upp: pairwise safety number (8-char groups):")
	assertLine(t, out, "upp:   "+sn)
	assertLine(t, out, "upp: compare this number with the peer over an independent channel")

	// Correct full-digest SN matches (exit 0).
	code, out, _ = runCLI(t, "", "verify", "-identity", aPath, "-peer", bPath, "-sn", sn)
	if code != 0 {
		t.Fatalf("matching -sn exit = %d", code)
	}
	assertLine(t, out, "upp: verified: pairwise safety number matched on both sides")

	// Wrong full-length SN: exact failure + recovery, exit 1.
	wrong := sn
	if wrong[0] == 'A' {
		wrong = "B" + wrong[1:]
	} else {
		wrong = "A" + wrong[1:]
	}
	code, _, errOut = runCLI(t, "", "verify", "-identity", aPath, "-peer", bPath, "-sn", wrong)
	if code != 1 {
		t.Fatalf("wrong -sn exit = %d; stderr:\n%s", code, errOut)
	}
	assertLine(t, errOut, "upp: unverified_safety_number: the safety numbers did not match; connection refused")
	assertLine(t, errOut, "  Next: repeat the comparison over an independent channel.")

	// Legacy 4-char code is a usage error, exit 2.
	code, _, errOut = runCLI(t, "", "verify", "-identity", aPath, "-peer", bPath, "-sn", "ABCD EFGH")
	if code != 2 {
		t.Fatalf("legacy -sn exit = %d; stderr:\n%s", code, errOut)
	}
	assertLine(t, errOut, `upp: usage error: -sn must be the 52-character pairwise safety number in 8-char groups; run "upp help"`)
}

// TestGrantCLIExitCodesStringsAndRevoke covers decline=3, grant=0, revoke and
// list, and the usage error for mutually exclusive revoke selectors.
func TestGrantCLIExitCodesStringsAndRevoke(t *testing.T) {
	dir := t.TempDir()
	id, idPath := saveTestIdentity(t, dir, "alice.json")
	fp := fmt.Sprintf("%x", id.Fingerprint())
	grants := filepath.Join(dir, "alice.grants")
	args := []string{"grant", "add", "-identity", idPath, "-grants", grants, "-peer-fp", fp, "-resource", "stream", "-op", "open,read,write"}

	// Explicit decline => exit 3, exact token, no file.
	code, _, errOut := runCLI(t, "no\n", args...)
	if code != 3 {
		t.Fatalf("decline exit = %d; stderr:\n%s", code, errOut)
	}
	// The prompt has no trailing newline, so with piped stdin the token follows
	// it on the same physical line; assert the token itself.
	if !strings.Contains(errOut, "upp: authorization_denied: operator declined the scoped grant") {
		t.Fatalf("decline token missing in:\n%s", errOut)
	}
	if _, err := os.Stat(grants); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("grant file written after decline")
	}

	// Consent => exit 0, granted line, 0600 file.
	code, out, errOut := runCLI(t, "yes\n", args...)
	if code != 0 {
		t.Fatalf("grant exit %d stderr %q", code, errOut)
	}
	if strings.Contains(errOut, "upp: ") {
		t.Fatalf("unexpected error status on successful grant: %q", errOut)
	}
	if !strings.HasPrefix(out, "upp: granted: grant ") {
		t.Fatalf("granted line missing: %q", out)
	}
	info, _ := os.Stat(grants)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("grant file mode = %o", info.Mode().Perm())
	}
	parts := strings.Fields(strings.TrimSpace(out))
	grantID := parts[3] // upp: granted: grant <ID> ...

	// Revoke by id and confirm list shows enabled=false.
	code, _, errOut = runCLI(t, "", "grant", "revoke", "-grants", grants, "-grant-id", grantID)
	if code != 0 || errOut != "" {
		t.Fatalf("revoke exit %d stderr %q", code, errOut)
	}
	code, out, _ = runCLI(t, "", "grant", "list", "-grants", grants)
	if code != 0 || !strings.Contains(out, "enabled=false") {
		t.Fatalf("list after revoke: exit %d out %q", code, out)
	}

	// Both selectors is a usage error.
	code, _, errOut = runCLI(t, "", "grant", "revoke", "-grants", grants, "-grant-id", grantID, "-peer-fp", fp)
	if code != 2 {
		t.Fatalf("dual-selector revoke exit = %d", code)
	}
	assertLine(t, errOut, `upp: usage error: exactly one of -grant-id or -peer-fp is required; run "upp help"`)
}

// TestShortFingerprintRejected guards full-fingerprint-only grant issuance.
func TestShortFingerprintRejected(t *testing.T) {
	dir := t.TempDir()
	_, idPath := saveTestIdentity(t, dir, "alice.json")
	code, _, errOut := runCLI(t, "yes\n", "grant", "add", "-identity", idPath, "-grants", filepath.Join(dir, "g"), "-peer-fp", "abcd")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	assertLine(t, errOut, `upp: usage error: -peer-fp must be the full 64-character lowercase hex fingerprint; run "upp help"`)
}
