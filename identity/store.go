package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type storedKey struct {
	PublicKey      []byte `json:"public_key"`
	Continuity     []byte `json:"continuity,omitempty"`
	Acknowledgment []byte `json:"acknowledgment,omitempty"`
	PrivateSeed    []byte `json:"private_seed,omitempty"`
}

type storedIdentity struct {
	Version       int         `json:"version"`
	Suite         string      `json:"suite"`
	ClassHint     string      `json:"class_hint,omitempty"`
	RootPublicKey []byte      `json:"root_public_key"`
	SelfBinding   []byte      `json:"self_binding"`
	Keys          []storedKey `json:"keys"`
	RevokedKeys   [][]byte    `json:"revoked_keys,omitempty"`
}

// Marshal encodes an identity for local storage. The private key seeds are
// included so the same process can sign after a restart; the file must be
// protected with 0600 permissions by Save.
func (id *Identity) Marshal() ([]byte, error) {
	if len(id.privateKeys) != len(id.KeyLog) {
		return nil, errors.New("cannot marshal: private keys unavailable")
	}
	stored := storedIdentity{
		Version:       id.Version,
		Suite:         id.Suite,
		ClassHint:     id.ClassHint,
		RootPublicKey: bytes.Clone(id.RootPublicKey),
		SelfBinding:   bytes.Clone(id.SelfBinding),
	}
	for i, rec := range id.KeyLog {
		stored.Keys = append(stored.Keys, storedKey{
			PublicKey:      bytes.Clone(rec.PublicKey),
			Continuity:     bytes.Clone(rec.Continuity),
			Acknowledgment: bytes.Clone(rec.Acknowledgment),
			PrivateSeed:    bytes.Clone(id.privateKeys[i].Seed()),
		})
	}
	for _, revoked := range id.RevokedKeys {
		stored.RevokedKeys = append(stored.RevokedKeys, bytes.Clone(revoked))
	}
	return json.MarshalIndent(stored, "", "  ")
}

// Parse decodes and verifies a locally stored identity.
func Parse(data []byte) (*Identity, error) {
	var stored storedIdentity
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("decode identity: %w", err)
	}
	if len(stored.Keys) == 0 {
		return nil, errors.New("identity has no keys")
	}
	if !bytes.Equal(stored.RootPublicKey, stored.Keys[0].PublicKey) {
		return nil, errors.New("root key does not match first key log entry")
	}

	id := &Identity{
		Version:       stored.Version,
		Suite:         stored.Suite,
		ClassHint:     stored.ClassHint,
		RootPublicKey: bytes.Clone(stored.RootPublicKey),
		SelfBinding:   bytes.Clone(stored.SelfBinding),
		RevokedKeys:   stored.RevokedKeys,
	}
	for _, key := range stored.Keys {
		rec := KeyRecord{
			PublicKey:      bytes.Clone(key.PublicKey),
			Continuity:     bytes.Clone(key.Continuity),
			Acknowledgment: bytes.Clone(key.Acknowledgment),
		}
		id.KeyLog = append(id.KeyLog, rec)
		if len(key.PrivateSeed) != ed25519.SeedSize {
			return nil, errors.New("invalid private key seed length")
		}
		priv := ed25519.NewKeyFromSeed(key.PrivateSeed)
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), rec.PublicKey) {
			return nil, errors.New("private key does not match public key")
		}
		id.privateKeys = append(id.privateKeys, priv)
	}
	if err := id.Verify(); err != nil {
		return nil, err
	}
	return id, nil
}

// Save writes an identity to path with 0600 permissions. It writes a temporary
// file in the same directory, sets its mode explicitly, and renames it over the
// target so the replacement is atomic and an existing loose mode is not kept.
func Save(path string, id *Identity) error {
	data, err := id.Marshal()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".identity-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary identity file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op after a successful rename; cleanup on error

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("set identity file permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write identity file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close identity file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace identity file: %w", err)
	}
	return nil
}

// Load reads and verifies an identity from path.
func Load(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity: %w", err)
	}
	return Parse(data)
}
