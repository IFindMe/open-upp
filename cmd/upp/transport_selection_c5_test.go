package main

// C5 CLI/toolchain coverage (ADR-002 §6/§7): Tailcat is the default for both
// listen and connect, TCP is explicit-only with no auto-downgrade, and the
// dependency pin / adapter isolation are reproducible.

import (
	"bytes"
	"context"
	"go/parser"
	"go/token"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IFindMe/open-upp/discovery"
)

// syncBuffer is safe to read while an exec.Cmd goroutine is still writing.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestNewTransportSelectionC5(t *testing.T) {
	tr, err := newTransport(discovery.TransportTailcat, 443)
	if err != nil || tr == nil || tr.Name() != "tailcat" {
		t.Fatalf("newTransport(tailcat) = %v, %v", tr, err)
	}
	tr, err = newTransport(discovery.TransportTCP, 443)
	if err != nil || tr == nil || tr.Name() != "tcp" {
		t.Fatalf("newTransport(tcp) = %v, %v", tr, err)
	}
	if tr, err := newTransport("bogus", 443); err == nil || tr != nil {
		t.Fatalf("newTransport(bogus) = %v, %v, want usage error", tr, err)
	}
}

func TestUsageDeclaresTailcatDefaultC5(t *testing.T) {
	code, out, errOut := runCLI(t, "", "help")
	if code != 0 || errOut != "" {
		t.Fatalf("upp help = %d, stderr %q", code, errOut)
	}
	for _, want := range []string{
		"Tailcat is the default transport",
		"-transport tailcat|tcp",
		"-transport tcp is an explicit local-test",
		"never downgrades",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("help missing %q:\n%s", want, out)
		}
	}
}

// TestListenDefaultsToTailcatC5 proves the default listen path writes a
// Tailcat hint (tc... capability, 0600) without any -transport flag.
func TestListenDefaultsToTailcatC5(t *testing.T) {
	dir := t.TempDir()
	_, idPath := saveTestIdentity(t, dir, "server.json")
	hintPath := filepath.Join(dir, "default.hint")

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	listen := exec.CommandContext(ctx, cliBin, "listen", "-identity", idPath,
		"-grants", filepath.Join(dir, "server.grants"), "-pins", filepath.Join(dir, "server.pins"),
		"-hint", hintPath, "-service-port", "44893")
	listen.Stdin = strings.NewReader("yes\n")
	var lOut, lErr syncBuffer
	listen.Stdout = &lOut
	listen.Stderr = &lErr
	if err := listen.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = listen.Wait() }()

	deadline := time.Now().Add(20 * time.Second)
	for {
		if st, err := os.Stat(hintPath); err == nil && st.Size() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("default listen did not write a hint; stdout=%q stderr=%q", lOut.String(), lErr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	info, err := os.Stat(hintPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("default hint mode = %o, want 600", info.Mode().Perm())
	}
	h, err := discovery.Load(hintPath)
	if err != nil {
		t.Fatal(err)
	}
	if h.Transport != discovery.TransportTailcat {
		t.Fatalf("default hint transport = %q, want tailcat", h.Transport)
	}
	if !strings.HasPrefix(h.Addr, "tc") {
		t.Fatalf("default hint addr is not a tc... capability: %q", h.Addr)
	}
	if strings.Contains(lOut.String(), h.Addr) || strings.Contains(lErr.String(), h.Addr) {
		t.Fatal("default listen leaked the capability into stdout/stderr")
	}
}

// TestConnectDefaultIgnoresHintTransportC5 proves connect uses the flag default
// (tailcat) and never auto-downgrades to TCP from an untrusted hint: the hint
// says "tcp" and a real TCP listener is up, yet the default dial fails as
// route_failed instead of switching backends.
func TestConnectDefaultIgnoresHintTransportC5(t *testing.T) {
	dir := t.TempDir()
	_, idPath := saveTestIdentity(t, dir, "client.json")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e == nil {
			_ = c.Close()
		}
	}()

	fp := strings.Repeat("ab", 32)
	hintPath := filepath.Join(dir, "tcpish.hint")
	data := `{"subject_fp":"` + fp + `","addr":"127.0.0.1","port":` +
		itoa(uint16(ln.Addr().(*net.TCPAddr).Port)) + `,"transport":"tcp"}`
	if err := os.WriteFile(hintPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	// No -transport flag: the default tailcat backend dials a non-capability
	// address and fails. It must not fall back to the TCP listener.
	code, _, errOut := runCLI(t, "yes\n", "connect", "-identity", idPath, "-hint", hintPath,
		"-grants", filepath.Join(dir, "missing.grants"), "-pins", filepath.Join(dir, "client.pins"),
		"-resource", "stream", "-op", "open,read,write")
	if code != 1 {
		t.Fatalf("connect exit = %d, want 1; stderr:\n%s", code, errOut)
	}
	if !strings.Contains(errOut, "upp: route_failed:") {
		t.Fatalf("expected tailcat route_failed (no auto-downgrade), got:\n%s", errOut)
	}
	if strings.Contains(errOut, "authorization_denied") || strings.Contains(errOut, "upp: peer authenticated:") {
		t.Fatalf("connect reached the TCP fallback gates:\n%s", errOut)
	}
}

func itoa(v uint16) string {
	if v == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func TestGoModTailcatPinC5(t *testing.T) {
	root := filepath.Join(".", "..", "..")
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(mod)
	if !strings.Contains(s, "require github.com/tailscale/tailcat v0.7.0") {
		t.Fatalf("go.mod does not pin tailcat v0.7.0 exactly:\n%s", s)
	}
	for _, bad := range []string{"tailcat v0.7.1", "tailcat >=v0.7.0", "tailcat ^v0.7.0", "tailcat v0.7.0 // indirect"} {
		if strings.Contains(s, bad) {
			t.Fatalf("go.mod has a non-exact tailcat requirement %q", bad)
		}
	}
	if !strings.Contains(s, "go 1.27.1") {
		t.Fatalf("go.mod lacks the required go 1.27.1 directive:\n%s", s)
	}
	sum, err := os.ReadFile(filepath.Join(root, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sum), "github.com/tailscale/tailcat v0.7.0 h1:") ||
		!strings.Contains(string(sum), "github.com/tailscale/tailcat v0.7.0/go.mod h1:") {
		t.Fatal("go.sum missing exact v0.7.0 module hashes")
	}
}

func TestTailcatImportIsolationC5(t *testing.T) {
	root := filepath.Join(".", "..", "..")
	const needle = "github.com/tailscale/tailcat"
	var importers []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".opencode", ".tasks", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Parse import declarations only: a literal mention of the module path
		// in a test assertion is not an import site.
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p == needle {
				rel, _ := filepath.Rel(root, path)
				importers = append(importers, filepath.ToSlash(rel))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(importers) != 1 || importers[0] != "transport/tailcat.go" {
		t.Fatalf("Tailcat import sites = %v, want only transport/tailcat.go", importers)
	}
}
