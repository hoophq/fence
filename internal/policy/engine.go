package policy

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/hoophq/leash/internal/analyzer/shell"
)

// Engine evaluates Actions against an ordered set of rules.
type Engine struct {
	rules         []Rule
	defaultEffect Effect
	home          string
}

// NewEngine builds an engine from one or more rulepacks. Later packs are
// appended after earlier ones; the default effect is taken from the last pack
// that sets one, falling back to allow. Rulepacks must already be validated
// (Load/LoadFile do this).
func NewEngine(packs ...*Rulepack) *Engine {
	e := &Engine{defaultEffect: EffectAllow}
	home, _ := os.UserHomeDir()
	e.home = home
	for _, p := range packs {
		if p == nil {
			continue
		}
		if p.Default != "" {
			e.defaultEffect = p.Default
		}
		e.rules = append(e.rules, p.Rules...)
	}
	return e
}

// Evaluate returns the decision for an action. When several rules match, the
// most severe effect wins (deny > ask > warn). When none match, the engine's
// default effect applies.
func (e *Engine) Evaluate(a Action) Decision {
	var analysis *shell.Analysis
	if a.Kind == ActionShell {
		got := shell.Analyze(a.Command, a.Cwd)
		analysis = &got
	}

	decision := Decision{Effect: e.defaultEffect}
	for i := range e.rules {
		r := &e.rules[i]
		if !e.matches(r, a, analysis) {
			continue
		}
		decision.Matched = append(decision.Matched, r)
		if r.Effect.severity() > decision.Effect.severity() {
			decision.Effect = r.Effect
			decision.Rule = r
		}
	}
	return decision
}

func (e *Engine) matches(r *Rule, a Action, analysis *shell.Analysis) bool {
	m := r.Match

	if len(m.Tool) > 0 && !containsKind(m.Tool, a.Kind) {
		return false
	}

	if m.Shell != nil {
		if a.Kind != ActionShell || analysis == nil || !matchShell(m.Shell, analysis) {
			return false
		}
	}

	if len(m.PathGlob) > 0 {
		if a.Kind != ActionFileWrite && a.Kind != ActionFileRead {
			return false
		}
		if !e.matchPathGlobs(m.PathGlob, a) {
			return false
		}
	}

	if r.url != nil {
		if a.Kind != ActionNetFetch || !r.url.MatchString(a.URL) {
			return false
		}
	}

	if r.regex != nil {
		if !r.regex.MatchString(rawText(a)) {
			return false
		}
	}

	return true
}

func matchShell(m *ShellMatch, a *shell.Analysis) bool {
	if m.RecursiveDelete && !a.RecursiveDelete {
		return false
	}
	if m.DeleteTarget != "" {
		switch m.DeleteTarget {
		case "any":
			if a.DeleteTarget == shell.TargetNone {
				return false
			}
		case "sensitive":
			if a.DeleteTarget != shell.TargetSensitive {
				return false
			}
		case "outside_workspace":
			if a.DeleteTarget != shell.TargetOutsideWorkspace {
				return false
			}
		}
	}
	if m.ForcePush && !a.ForcePush {
		return false
	}
	if m.HistoryRewrite && !a.HistoryRewrite {
		return false
	}
	if m.PipeToShell && !a.PipeToShellFromNet {
		return false
	}
	if m.SecretExfil != "" {
		// Exfiltration = a secret is read AND data leaves over the network.
		if !a.NetEgress || a.SecretRead == shell.SecretNone {
			return false
		}
		if m.SecretExfil == "high" && a.SecretRead != shell.SecretHigh {
			return false
		}
	}
	if len(m.CommandIn) > 0 && !a.Has(m.CommandIn...) {
		return false
	}
	return true
}

func (e *Engine) matchPathGlobs(globs []string, a Action) bool {
	path := e.absPath(a.Path, a.Cwd)
	for _, g := range globs {
		pattern := e.expandHome(g)
		if ok, _ := doublestar.Match(pattern, path); ok {
			return true
		}
		// Also match against the raw (unexpanded) path so a glob like **/.env
		// works regardless of absolute resolution.
		if ok, _ := doublestar.Match(pattern, a.Path); ok {
			return true
		}
	}
	return false
}

func (e *Engine) absPath(path, cwd string) string {
	p := e.expandHome(path)
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	if cwd != "" {
		return filepath.Clean(filepath.Join(cwd, p))
	}
	return filepath.Clean(p)
}

func (e *Engine) expandHome(p string) string {
	if e.home == "" {
		return p
	}
	if p == "~" {
		return e.home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(e.home, p[2:])
	}
	return p
}

func containsKind(kinds []ActionKind, k ActionKind) bool {
	for _, x := range kinds {
		if x == k {
			return true
		}
	}
	return false
}

func rawText(a Action) string {
	switch a.Kind {
	case ActionShell:
		return a.Command
	case ActionFileWrite, ActionFileRead:
		return a.Path
	case ActionNetFetch:
		return a.URL
	default:
		return ""
	}
}
