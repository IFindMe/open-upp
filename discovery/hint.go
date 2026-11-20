// Package discovery implements the untrusted, out-of-band endpoint hint used
// as the v1 routing seam (W3 D3, protocol-v1.md §1/§6). A hint is a locator
// only: it is never identity evidence and never an authorization input.
package discovery

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

// Hint locates one peer. SubjectFP is a routing consistency check, not proof
// of identity; the handshake authenticates the peer independently.
type Hint struct {
	SubjectFP [32]byte `json:"subject_fp"`
	Addr      string   `json:"addr"`
	Port      uint16   `json:"port"`
}

type storedHint struct {
	SubjectFP string `json:"subject_fp"`
	Addr      string `json:"addr"`
	Port      uint16 `json:"port"`
}

// Target returns the dialable host:port for this hint.
func (h Hint) Target() string {
	return net.JoinHostPort(h.Addr, strconv.Itoa(int(h.Port)))
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
	if st.Addr == "" || st.Port == 0 {
		return Hint{}, errors.New("hint address or port missing")
	}
	var h Hint
	copy(h.SubjectFP[:], raw)
	h.Addr = st.Addr
	h.Port = st.Port
	return h, nil
}

// Save writes a hint with mode 0600 using an atomic same-directory rename.
func Save(path string, h Hint) error {
	data, err := json.MarshalIndent(storedHint{
		SubjectFP: hex.EncodeToString(h.SubjectFP[:]),
		Addr:      h.Addr,
		Port:      h.Port,
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
