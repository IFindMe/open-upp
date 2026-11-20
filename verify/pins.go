package verify

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Change classifies how a presented identity differs from the retained pin.
// It is advisory only; every class still requires fresh PoP, valid continuity
// and a fresh out-of-band confirmation before verification succeeds.
type Change int

const (
	ChangeFirst Change = iota // no retained pin for this peer
	ChangeNone                // same fingerprint and current key
	ChangeKey                 // same fingerprint, valid successor key (rotation)
	ChangeRoot                // fingerprint changed; full re-verification required
)

// Pin is retained change-detection state for the single counterparty of the
// two-peer slice. Degraded/TOFU state is deliberately not represented: v1 has
// no input path that can set it (W5c).
type Pin struct {
	SubjectFP       string `json:"subject_fp"` // full 64-hex fingerprint
	LastVerifiedKey string `json:"last_verified_key"`
	SNDigest        string `json:"sn_digest"`
}

// Store is a 0600 pin file holding at most one counterparty pin.
type Store struct {
	path string
	pin  *Pin
}

// Load reads a pin store; a missing file yields an empty store.
func Load(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read pins: %w", err)
	}
	var p Pin
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("decode pins: %w", err)
	}
	if p.SubjectFP != "" {
		s.pin = &p
	}
	return s, nil
}

// Check compares the presented identity with retained state. It never returns
// an authority decision; the caller must still independently verify the peer.
func (s *Store) Check(fp [32]byte, key []byte) Change {
	if s.pin == nil {
		return ChangeFirst
	}
	if s.pin.SubjectFP != hex.EncodeToString(fp[:]) {
		return ChangeRoot
	}
	if s.pin.LastVerifiedKey == hex.EncodeToString(key) {
		return ChangeNone
	}
	return ChangeKey
}

// Commit records a verified fingerprint/key/digest. Call it only after a fresh
// out-of-band full-digest confirmation has succeeded. Committing a new root
// replaces the previous pin; it never carries a grant forward.
func (s *Store) Commit(fp [32]byte, key []byte, digest [32]byte) error {
	s.pin = &Pin{
		SubjectFP:       hex.EncodeToString(fp[:]),
		LastVerifiedKey: hex.EncodeToString(key),
		SNDigest:        hex.EncodeToString(digest[:]),
	}
	return s.Save()
}

// Save writes the pin store atomically with mode 0600.
func (s *Store) Save() error {
	var data []byte
	var err error
	if s.pin == nil {
		data = []byte("{}\n")
	} else {
		data, err = json.MarshalIndent(s.pin, "", "  ")
		if err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".pins-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary pin file: %w", err)
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
	return os.Rename(tmpPath, s.path)
}
