package policy

import (
	"fmt"
	"regexp"
)

// Rule is a single guardrail. A rule matches an Action when every condition set
// in Match is satisfied (logical AND). Conditions left empty are ignored.
type Rule struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity,omitempty"` // info|low|medium|high|critical, display only
	Effect      Effect `yaml:"effect"`
	Message     string `yaml:"message,omitempty"` // shown to the user when matched
	Match       Match  `yaml:"match"`

	regex *regexp.Regexp // compiled form of Match.Regex
	url   *regexp.Regexp // compiled form of Match.URLRegex
}

// Match is the condition of a rule. An empty Match never matches (rules must be
// specific); a non-empty Match requires all of its set conditions to hold.
type Match struct {
	// Tool restricts the rule to specific action kinds (shell, file_write,
	// file_read, net_fetch). Empty means any kind.
	Tool []ActionKind `yaml:"tool,omitempty"`

	// Shell matches semantic facts about a shell command.
	Shell *ShellMatch `yaml:"shell,omitempty"`

	// PathGlob matches file_write/file_read paths against doublestar globs.
	// A leading ~/ is expanded to the user's home directory.
	PathGlob []string `yaml:"path_glob,omitempty"`

	// URLRegex matches net_fetch URLs.
	URLRegex string `yaml:"url_regex,omitempty"`

	// Regex is a raw fallback matched against the command/path/url. Prefer the
	// structured matchers above; use this only for patterns the analyzer does
	// not yet model (e.g. fork bombs).
	Regex string `yaml:"regex,omitempty"`
}

// ShellMatch matches against facts produced by the shell analyzer.
type ShellMatch struct {
	RecursiveDelete bool     `yaml:"recursive_delete,omitempty"`
	DeleteTarget    string   `yaml:"delete_target,omitempty"` // sensitive|outside_workspace|any
	ForcePush       bool     `yaml:"force_push,omitempty"`
	HistoryRewrite  bool     `yaml:"history_rewrite,omitempty"`
	PipeToShell     bool     `yaml:"pipe_to_shell,omitempty"`
	SecretExfil     string   `yaml:"secret_exfil,omitempty"` // high|any
	CommandIn       []string `yaml:"command_in,omitempty"`
}

func (m Match) isEmpty() bool {
	return len(m.Tool) == 0 && m.Shell == nil && len(m.PathGlob) == 0 &&
		m.URLRegex == "" && m.Regex == ""
}

// compile validates and pre-compiles the rule's regular expressions.
func (r *Rule) compile() error {
	if r.ID == "" {
		return fmt.Errorf("rule is missing an id")
	}
	if !r.Effect.Valid() {
		return fmt.Errorf("rule %q has invalid effect %q", r.ID, r.Effect)
	}
	if r.Match.isEmpty() {
		return fmt.Errorf("rule %q has an empty match (would never fire)", r.ID)
	}
	if dt := r.Match.Shell; dt != nil && dt.DeleteTarget != "" {
		switch dt.DeleteTarget {
		case "sensitive", "outside_workspace", "any":
		default:
			return fmt.Errorf("rule %q has invalid delete_target %q", r.ID, dt.DeleteTarget)
		}
	}
	if sh := r.Match.Shell; sh != nil && sh.SecretExfil != "" {
		switch sh.SecretExfil {
		case "high", "any":
		default:
			return fmt.Errorf("rule %q has invalid secret_exfil %q", r.ID, sh.SecretExfil)
		}
	}
	if r.Match.Regex != "" {
		re, err := regexp.Compile(r.Match.Regex)
		if err != nil {
			return fmt.Errorf("rule %q has invalid regex: %w", r.ID, err)
		}
		r.regex = re
	}
	if r.Match.URLRegex != "" {
		re, err := regexp.Compile(r.Match.URLRegex)
		if err != nil {
			return fmt.Errorf("rule %q has invalid url_regex: %w", r.ID, err)
		}
		r.url = re
	}
	return nil
}
