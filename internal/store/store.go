// Package store manages Leash's user-level state directory (~/.leash): the
// rulepacks installed from a registry, and the lockfile recording where each
// came from. The packs directory is the source of truth for what is active;
// the lockfile is metadata for update/search, so a damaged lockfile can never
// disable protection.
package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hoophq/leash/internal/policy"
)

// Store is a Leash state directory.
type Store struct{ dir string }

// Open returns a Store rooted at dir. The directory need not exist yet.
func Open(dir string) *Store { return &Store{dir: dir} }

// DefaultDir returns the default state directory, ~/.leash.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".leash"), nil
}

// packExts are the extensions a pack file may carry inside the store; Install
// always writes the first.
var packExts = []string{".yaml", ".yml"}

func (s *Store) packsDir() string { return filepath.Join(s.dir, "packs") }

// PackPath returns where the pack named name is (or would be) installed.
func (s *Store) PackPath(name string) string {
	return filepath.Join(s.packsDir(), name+".yaml")
}

// List returns the names of installed packs, sorted. A store that has never
// been used is not an error — it is just empty.
func (s *Store) List() ([]string, error) {
	entries, err := os.ReadDir(s.packsDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if name, ok := trimPackExt(e.Name()); ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// trimPackExt strips a recognised pack extension, reporting whether the file
// name carried one.
func trimPackExt(name string) (string, bool) {
	for _, ext := range packExts {
		if trimmed, ok := strings.CutSuffix(name, ext); ok {
			return trimmed, true
		}
	}
	return "", false
}

// Locate resolves an installed pack name to its file path. It satisfies
// policy.LocateFunc.
func (s *Store) Locate(name string) (string, bool) {
	if !ValidName(name) {
		return "", false
	}
	for _, ext := range packExts {
		p := filepath.Join(s.packsDir(), name+ext)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p, true
		}
	}
	return "", false
}

// Has reports whether a pack named name is installed.
func (s *Store) Has(name string) bool {
	_, ok := s.Locate(name)
	return ok
}

// Install validates data as a rulepack and writes it as name, returning the
// parsed pack. Nothing is written when validation fails.
func (s *Store) Install(name string, data []byte) (*policy.Rulepack, error) {
	if !ValidName(name) {
		return nil, fmt.Errorf("invalid pack name %q", name)
	}
	pack, err := policy.Load(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("pack %q: %w", name, err)
	}
	if err := os.MkdirAll(s.packsDir(), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(s.PackPath(name), data, 0o644); err != nil {
		return nil, err
	}
	return pack, nil
}

// Remove deletes the installed pack named name.
func (s *Store) Remove(name string) error {
	path, ok := s.Locate(name)
	if !ok {
		return fmt.Errorf("pack %q is not installed", name)
	}
	return os.Remove(path)
}

// ValidName reports whether name is usable as an installed pack name: a bare
// name with no path separators, traversal, or extension — it must name a file
// directly under the store's packs directory.
func ValidName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\`) {
		return false
	}
	if _, ok := trimPackExt(name); ok {
		return false
	}
	return name == filepath.Base(name)
}
