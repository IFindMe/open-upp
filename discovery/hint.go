// Package discovery implements the untrusted, out-of-band endpoint hint used
// as the routing seam (W3 D3, ADR-002). A hint is a locator only: it is never
// identity evidence and never an authorization input. For Tailcat its Addr is
// an opaque tc... capability stored verbatim in a 0600 file.
package discovery

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// Transport discriminator values. This is a closed set naming the seam
// implementation, not a trust or authority signal.
const (
	TransportTailcat = "tailcat"
	TransportTCP     = "tcp"
)

// maxAddrLen bounds a hint locator so an oversized value cannot be planted in
// the 0600 file. It is a syntactic guard, not a cryptographic check.
const maxAddrLen = 8192

// Hint locates one peer. SubjectFP is a routing consistency check, not proof
// of identity; the handshake authenticates the peer independently. Addr and
// Port identify the endpoint; Transport selects the dialer and confers no
// trust. None of these fields may be derived into identity or a grant.
type Hint struct {
	SubjectFP [32]byte `json:"subject_fp"`
	Addr      string   `json:"addr"`
	Port      uint16   `json:"port"`
	Transport string   `json:"transport"`
}

type storedHint struct {
	SubjectFP string `json:"subject_fp"`
	Addr      string `json:"addr"`
	Port      uint16 `json:"port"`
	Transport string `json:"transport"`
}

// validTransport reports whether s is in the closed discriminator set.
func validTransport(s string) bool {
	return s == TransportTailcat || s == TransportTCP
}

// validateAddr applies shape-only checks. The capability is never parsed or
// interpreted, and error text never echoes it.
func validateAddr(addr, transport string) error {
	if addr == "" {
		return errors.New("hint address or port missing")
	}
	if len(addr) > maxAddrLen {
		return errors.New("hint address is too long")
	}
	for _, r := range addr {
		if unicode.IsControl(r) {
			return errors.New("hint address contains a control character")
		}
	}
	if transport == TransportTailcat && !strings.HasPrefix(addr, "tc") {
		return errors.New("hint tailcat address is malformed")
	}
	return nil
}

// Load reads and validates a hint file.
func Load(path string) (Hint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Hint{}, fmt.Errorf("read hint: %w", err)
	}
	var st storedHint
	if err := json.Unmarshal(data, &st); err != nil {
		return Hint{}, fmt.Errorf("decode hint: %w", err)
	}
	raw, err := hex.DecodeString(st.SubjectFP)
	if err != nil || len(raw) != 32 {
		return Hint{}, errors.New("hint subject fingerprint must be 64 hex characters")
	}
	if st.Port == 0 {
		return Hint{}, errors.New("hint address or port missing")
	}
	if !validTransport(st.Transport) {
		return Hint{}, errors.New("hint transport is invalid")
	}
	if err := validateAddr(st.Addr, st.Transport); err != nil {
		return Hint{}, err
	}
	var h Hint
	copy(h.SubjectFP[:], raw)
	h.Addr = st.Addr
	h.Port = st.Port
	h.Transport = st.Transport
	return h, nil
}

// Save writes a hint with mode 0600 using an atomic same-directory rename.
func Save(path string, h Hint) error {
	data, err := json.MarshalIndent(storedHint{
		SubjectFP: hex.EncodeToString(h.SubjectFP[:]),
		Addr:      h.Addr,
		Port:      h.Port,
		Transport: h.Transport,
	}, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hint-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary hint file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// Resolver reads hints from a fixed path.
type Resolver struct{ Path string }

// Resolve loads the hint and checks its subject fingerprint against the
// expected peer identity. A mismatch is a routing failure, not an authority
// decision; it cannot bypass the handshake.
func (r Resolver) Resolve(expected [32]byte) (Hint, error) {
	h, err := Load(r.Path)
	if err != nil {
		return Hint{}, err
	}
	if h.SubjectFP != expected {
		return Hint{}, errors.New("hint subject fingerprint does not match the expected peer")
	}
	return h, nil
}
