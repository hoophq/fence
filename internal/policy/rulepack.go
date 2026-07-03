package policy

import (
	"embed"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed builtin/recommended.yaml
var builtinFS embed.FS

// Rulepack is a named, shareable collection of rules — the unit users publish
// and compose. The shipped "recommended" pack is embedded in the binary.
type Rulepack struct {
	Name string `yaml:"name"`
	// Default is the effect applied when no rule matches. Last pack to set it wins.
	Default Effect `yaml:"default,omitempty"`
	// Extends pulls other packs in below this one: each entry is an installed
	// pack name or a file path relative to this file. A Resolver flattens the
	// chain so this pack's rules, overrides, and default win.
	Extends []string `yaml:"extends,omitempty"`
	// Overrides retunes existing rules by id, changing only their effect
	// (e.g. soften a recommended deny to ask). Applied across all packs once
	// rules are pooled; later packs win.
	Overrides map[string]Effect `yaml:"overrides,omitempty"`
	Rules     []Rule            `yaml:"rules"`
}

// Load parses and validates a rulepack from r.
func Load(r io.Reader) (*Rulepack, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var pack Rulepack
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return nil, fmt.Errorf("parse rulepack: %w", err)
	}
	if err := pack.validate(); err != nil {
		return nil, err
	}
	return &pack, nil
}

// LoadFile parses and validates a rulepack from a file path.
func LoadFile(path string) (*Rulepack, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pack, err := Load(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return pack, nil
}

// RecommendedName is the name of the embedded, always-active pack.
const RecommendedName = "recommended"

// Recommended returns the rulepack shipped with Leash.
func Recommended() *Rulepack {
	f, err := builtinFS.Open("builtin/recommended.yaml")
	if err != nil {
		panic(fmt.Sprintf("leash: embedded recommended pack missing: %v", err))
	}
	defer f.Close()
	pack, err := Load(f)
	if err != nil {
		// A broken embedded pack is a build-time defect, not a runtime input.
		panic(fmt.Sprintf("leash: embedded recommended pack invalid: %v", err))
	}
	return pack
}

func (p *Rulepack) validate() error {
	if p.Default != "" && !p.Default.Valid() {
		return fmt.Errorf("rulepack %q has invalid default effect %q", p.Name, p.Default)
	}
	for _, ref := range p.Extends {
		if strings.TrimSpace(ref) == "" {
			return fmt.Errorf("rulepack %q has an empty extends entry", p.Name)
		}
	}
	for id, eff := range p.Overrides {
		if !eff.Valid() {
			return fmt.Errorf("rulepack %q: override for %q has invalid effect %q", p.Name, id, eff)
		}
	}
	ids := map[string]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		if err := r.compile(); err != nil {
			return err
		}
		if ids[r.ID] {
			return fmt.Errorf("rulepack %q has duplicate rule id %q", p.Name, r.ID)
		}
		ids[r.ID] = true
	}
	return nil
}
