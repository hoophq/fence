package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// LockSchema is the packs.lock.json schema this build writes.
const LockSchema = 1

// LockEntry records where an installed pack came from.
type LockEntry struct {
	Version     string    `json:"version"`
	SHA256      string    `json:"sha256"`
	Source      string    `json:"source"` // the registry index it was installed from
	InstalledAt time.Time `json:"installed_at"`
}

// NewLockEntry stamps a lock entry for a pack installed right now.
func NewLockEntry(version, sha256, source string) LockEntry {
	return LockEntry{Version: version, SHA256: sha256, Source: source, InstalledAt: time.Now().UTC()}
}

// Lockfile is the metadata sidecar for installed packs. It never decides what
// is active — the packs directory does — it only remembers versions and
// sources for `leash update` and `leash search`.
type Lockfile struct {
	Schema int                  `json:"schema"`
	Packs  map[string]LockEntry `json:"packs"`
}

func (s *Store) lockPath() string { return filepath.Join(s.dir, "packs.lock.json") }

// Lockfile reads the store's lockfile; a missing file is an empty lockfile.
func (s *Store) Lockfile() (*Lockfile, error) {
	lf := &Lockfile{Schema: LockSchema, Packs: map[string]LockEntry{}}
	data, err := os.ReadFile(s.lockPath())
	if errors.Is(err, os.ErrNotExist) {
		return lf, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, lf); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", s.lockPath(), err)
	}
	if lf.Packs == nil {
		lf.Packs = map[string]LockEntry{}
	}
	return lf, nil
}

// SaveLockfile writes the lockfile, creating the store directory if needed.
func (s *Store) SaveLockfile(lf *Lockfile) error {
	lf.Schema = LockSchema
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	out, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(s.lockPath(), out, 0o644)
}
