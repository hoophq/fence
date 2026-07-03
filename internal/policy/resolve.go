package policy

import (
	"fmt"
	"path/filepath"
	"strings"
)

// LocateFunc resolves an installed rulepack name to a file path, reporting
// ok=false when no pack by that name is installed. A nil LocateFunc never
// finds anything.
type LocateFunc func(name string) (path string, ok bool)

// Resolver flattens rulepack files and their extends: chains into the ordered
// pack list NewEngine expects: every pack a file extends is placed before it,
// so the extending pack's rules, overrides, and default win under the engine's
// later-pack-wins semantics. Packs are deduplicated by file identity across
// all Add calls on one Resolver, and a cyclic reference is skipped rather than
// followed — both are warnings, never errors, so a bad reference costs only
// itself, not the engine.
type Resolver struct {
	locate   LocateFunc
	visited  map[string]bool // canonical path -> fully resolved and appended
	visiting map[string]bool // canonical path -> on the current descent (cycle guard)
	packs    []*Rulepack
	warnings []string
}

// NewResolver returns a Resolver that resolves installed-pack references
// through locate.
func NewResolver(locate LocateFunc) *Resolver {
	return &Resolver{
		locate:   locate,
		visited:  map[string]bool{},
		visiting: map[string]bool{},
	}
}

// Add loads the rulepack at path, resolves its extends chain, and appends any
// packs not already seen (bases first, the pack itself last). Failing to load
// path itself is an error; a reference that cannot be resolved degrades to a
// warning.
func (r *Resolver) Add(path string) error {
	key := canonicalPath(path)
	if r.visited[key] {
		return nil
	}
	pack, err := LoadFile(path)
	if err != nil {
		return err
	}
	r.resolve(pack, key)
	return nil
}

// Packs returns the accumulated packs: deduplicated, every base before the
// packs that extend it, roots in the order they were added.
func (r *Resolver) Packs() []*Rulepack { return r.packs }

// Warnings returns non-fatal issues met while resolving: missing or cyclic
// extends references.
func (r *Resolver) Warnings() []string { return r.warnings }

func (r *Resolver) resolve(pack *Rulepack, key string) {
	r.visiting[key] = true
	for _, ref := range pack.Extends {
		target, ok := r.target(pack, key, ref)
		if !ok {
			continue
		}
		tkey := canonicalPath(target)
		if r.visited[tkey] {
			continue
		}
		if r.visiting[tkey] {
			r.warnf("%s: extends %q forms a cycle (skipped)", describePack(pack, key), ref)
			continue
		}
		base, err := LoadFile(target)
		if err != nil {
			r.warnf("%s: extends %q: %v (skipped)", describePack(pack, key), ref, err)
			continue
		}
		r.resolve(base, tkey)
	}
	delete(r.visiting, key)
	r.visited[key] = true
	r.packs = append(r.packs, pack)
}

// target resolves one extends reference to a file path. A reference containing
// a path separator or ending in .yaml/.yml is a file path relative to the
// referencing file; anything else is an installed pack name.
func (r *Resolver) target(pack *Rulepack, key, ref string) (string, bool) {
	if isPathRef(ref) {
		if filepath.IsAbs(ref) {
			return ref, true
		}
		return filepath.Join(filepath.Dir(key), ref), true
	}
	if ref == RecommendedName {
		r.warnf("%s: extends %q is unnecessary — the recommended pack is always active (skipped)",
			describePack(pack, key), ref)
		return "", false
	}
	if r.locate != nil {
		if p, ok := r.locate(ref); ok {
			return p, true
		}
	}
	r.warnf("%s: extends %q, which is not installed (run: leash add %s)", describePack(pack, key), ref, ref)
	return "", false
}

func (r *Resolver) warnf(format string, args ...any) {
	r.warnings = append(r.warnings, fmt.Sprintf(format, args...))
}

func isPathRef(ref string) bool {
	return strings.ContainsAny(ref, `/\`) ||
		strings.HasSuffix(ref, ".yaml") || strings.HasSuffix(ref, ".yml")
}

func canonicalPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return filepath.Clean(path)
}

func describePack(pack *Rulepack, key string) string {
	if pack.Name != "" {
		return fmt.Sprintf("pack %q", pack.Name)
	}
	return key
}
