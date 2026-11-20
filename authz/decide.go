package authz

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/IFindMe/open-upp/spec"
)

// ErrDenied is returned for every non-authorized decision. The caller renders
// the stable authorization_denied token with the full peer fingerprint.
var ErrDenied = errors.New("authorization denied")

// Scope is the authority returned by an authorized decision.
type Scope struct {
	GrantID  string
	Resource string
	Ops      []string
}

// Store is a local, 0600 grant file.
type Store struct {
	path   string
	grants []Grant
}

// Load reads a grant store; a missing file yields an empty store.
func Load(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read grants: %w", err)
	}
	if err := json.Unmarshal(data, &s.grants); err != nil {
		return nil, fmt.Errorf("decode grants: %w", err)
	}
	return s, nil
}

// Save writes the grant store atomically with mode 0600.
func (s *Store) Save() error {
	data, err := json.MarshalIndent(s.grants, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".grants-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary grant file: %w", err)
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

// Add appends a valid grant, enforcing the frozen grant bound.
func (s *Store) Add(g Grant) error {
	if !g.Verify() {
		return errors.New("grant signature is invalid")
	}
	if len(s.grants) >= spec.MaxGrants {
		return fmt.Errorf("grant store is full (%d)", spec.MaxGrants)
	}
	for _, existing := range s.grants {
		if existing.ID == g.ID {
			return errors.New("grant id already exists")
		}
	}
	s.grants = append(s.grants, g)
	return s.Save()
}

// Revoke sets enabled=false on one grant (no timestamps, no propagation).
func (s *Store) Revoke(id string) error {
	found := false
	for i := range s.grants {
		if s.grants[i].ID == id {
			s.grants[i].Enabled = false
			found = true
		}
	}
	if !found {
		return fmt.Errorf("grant %s not found", id)
	}
	return s.Save()
}

// List returns copies of non-secret grant metadata.
func (s *Store) List() []Grant {
	out := make([]Grant, 0, len(s.grants))
	for _, g := range s.grants {
		g.Signature = ""
		g.AuthorityKey = ""
		out = append(out, g)
	}
	return out
}

// Decide is the only path to AUTHORIZED. It requires an exact enabled grant,
// a matching resource, the requested op in the grant's op set, and a valid
// grant signature. Nothing outside this function may produce a Scope.
func (s *Store) Decide(subjectFP [32]byte, resource, op string) (Scope, error) {
	want := hex.EncodeToString(subjectFP[:])
	for _, g := range s.grants {
		if g.SubjectFP != want || !g.Enabled || g.Resource != resource || !g.Verify() {
			continue
		}
		for _, granted := range g.Ops {
			if granted == op {
				return Scope{GrantID: g.ID, Resource: g.Resource, Ops: append([]string(nil), g.Ops...)}, nil
			}
		}
	}
	return Scope{}, ErrDenied
}
