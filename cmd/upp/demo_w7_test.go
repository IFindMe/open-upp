package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestTwoPeerDemoScript runs the reproducible two-process demo end to end from
// the documented command alone (W7-AC6 / area 8).
func TestTwoPeerDemoScript(t *testing.T) {
	root, err := filepath.Abs(filepath.Join(".", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "scripts/two-peer-demo.sh")
	cmd.Dir = root
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("demo failed: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errOut.String())
	}
	if ctx.Err() != nil {
		t.Fatal("demo timed out")
	}
	s := out.String()
	if strings.Count(s, "upp: ended: session closed; session keys zeroized") < 2 {
		t.Fatalf("both peers did not reach ended:\n%s", s)
	}
	if !strings.Contains(s, "hello from Bob") || !strings.Contains(s, "pairwise safety number (8-char groups):") {
		t.Fatalf("echo or SN display missing:\n%s", s)
	}
	if !strings.Contains(s, "demo complete") {
		t.Fatal("demo completion marker missing")
	}
}

// TestCLITwoProcessNoGrantDenied verifies the CLI's exact authorization_denied
// rendering across two real processes, with a full fingerprint and no pin on
// the denied side.
func TestCLITwoProcessNoGrantDenied(t *testing.T) {
	dir := t.TempDir()
	serverID, sPath := saveTestIdentity(t, dir, "server.json")
	clientID, cPath := saveTestIdentity(t, dir, "client.json")
	clientFP := fmt.Sprintf("%x", clientID.Fingerprint())
	serverFP := fmt.Sprintf("%x", serverID.Fingerprint())

	// Server grants the client, but the client's grant file is absent.
	grantArgs := []string{"grant", "add", "-identity", sPath, "-grants", filepath.Join(dir, "server.grants"),
		"-peer-fp", clientFP, "-resource", "stream", "-op", "open,read,write"}
	code, _, ce := runCLI(t, "yes\n", grantArgs...)
	if code != 0 {
		t.Fatalf("server grant failed: %d %s", code, ce)
	}

	hintPath := filepath.Join(dir, "server.hint")
	listenCtx, stopListen := context.WithCancel(context.Background())
	defer stopListen()
	// The explicit TCP fallback keeps this deterministic two-process gate test
	// independent of Tailcat/DERP availability (ADR-002 §6.7).
	listen := exec.CommandContext(listenCtx, cliBin, "listen", "-identity", sPath,
		"-grants", filepath.Join(dir, "server.grants"), "-pins", filepath.Join(dir, "server.pins"),
		"-hint", hintPath, "-transport", "tcp", "-addr", "127.0.0.1:0")
	listen.Stdin = strings.NewReader("yes\n")
	var lOut, lErr bytes.Buffer
	listen.Stdout = &lOut
	listen.Stderr = &lErr
	if err := listen.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stopListen(); _ = listen.Wait() }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if st, err := os.Stat(hintPath); err == nil && st.Size() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener did not write hint; stdout=%q stderr=%q", lOut.String(), lErr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	code, _, errOut := runCLI(t, "yes\n", "connect", "-identity", cPath, "-hint", hintPath,
		"-grants", filepath.Join(dir, "client.missing.grants"), "-pins", filepath.Join(dir, "client.pins"),
		"-transport", "tcp", "-resource", "stream", "-op", "open,read,write")
	if code != 1 {
		t.Fatalf("connect exit = %d, want 1; stderr:\n%s", code, errOut)
	}
	wantLine := "upp: authorization_denied: no enabled scoped grant covers peer " + serverFP + " for stream/open"
	if !strings.Contains(errOut, wantLine) {
		t.Fatalf("missing authorization_denied line %q in:\n%s", wantLine, errOut)
	}
	if !strings.Contains(errOut, "Next: an administrator must run upp grant add; verification alone is not a grant") {
		t.Fatalf("missing recovery line in:\n%s", errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "client.pins")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("client pin written despite grant denial")
	}
}
