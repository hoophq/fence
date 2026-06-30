// Package policy defines Leash's agent-neutral guardrail model: the normalized
// Action an agent wants to perform, the Effect a rule applies, and the Engine
// that evaluates rulepacks against an Action.
//
// Adapters (one per agent: Claude Code, Codex, ...) translate an agent's tool
// call into an Action. The engine and rulepacks know nothing about any specific
// agent, which is what lets a single rulepack be portable across agents.
package policy

// ActionKind is the category of operation an agent is attempting.
type ActionKind string

const (
	ActionShell     ActionKind = "shell"
	ActionFileWrite ActionKind = "file_write"
	ActionFileRead  ActionKind = "file_read"
	ActionNetFetch  ActionKind = "net_fetch"
	ActionUnknown   ActionKind = ""
)

// Action is a normalized, agent-neutral description of something an agent wants
// to do. Only the fields relevant to Kind are populated.
type Action struct {
	Kind ActionKind

	Command string // ActionShell: the shell command
	Path    string // ActionFileWrite/ActionFileRead: the target file path
	URL     string // ActionNetFetch: the URL

	Cwd  string // working directory, used for workspace-relative reasoning
	Tool string // original agent tool name (e.g. "Bash"), for diagnostics
}

// Effect is the outcome a rule applies when it matches. Effects are ordered by
// severity so that, when several rules match, the most severe one wins
// (deny-overrides).
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectWarn  Effect = "warn"
	EffectAsk   Effect = "ask"
	EffectDeny  Effect = "deny"
)

func (e Effect) severity() int {
	switch e {
	case EffectDeny:
		return 3
	case EffectAsk:
		return 2
	case EffectWarn:
		return 1
	default:
		return 0
	}
}

// Valid reports whether e is a recognised effect.
func (e Effect) Valid() bool {
	switch e {
	case EffectAllow, EffectWarn, EffectAsk, EffectDeny:
		return true
	default:
		return false
	}
}

// Decision is the result of evaluating an Action against a set of rules.
type Decision struct {
	Effect  Effect
	Rule    *Rule // the rule responsible for Effect (nil if defaulted)
	Matched []*Rule
}
