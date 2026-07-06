package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// toolMatcher is the Claude Code tool-name regexp Fence hooks into: the tools
// whose actions the engine actually evaluates.
const toolMatcher = "Bash|Write|Edit|MultiEdit|NotebookEdit|WebFetch"

// codexToolMatcher is the Codex equivalent: shell commands plus file edits
// (which Codex performs through its apply_patch tool). Anchored because Codex
// matchers are regexes searched against the tool name.
const codexToolMatcher = "^(Bash|apply_patch)$"

// sessionStartMatcher fires the banner when a session begins or is cleared,
// but not after every context compaction. Both agents use the same sources.
const sessionStartMatcher = "startup|resume|clear"

// hookAgent describes one agent fence can wire its hooks into: where the
// hooks file lives, what shape identifies our entries, and what the matchers
// are. Both agents speak the same {"hooks": {...}} JSON shape, so the
// converge/remove machinery is shared.
type hookAgent struct {
	name           string // CLI argument and hook subcommand
	display        string // how the agent is named in messages
	dir            string // settings directory under the project or home
	file           string // hooks file inside dir
	invocation     string // the bare invocation containsHook keys on
	preMatcher     string
	sessionMatcher string
	trustNote      string // printed after install (Codex's hook-trust step)
}

var hookAgents = []hookAgent{
	{
		name:           "claude-code",
		display:        "Claude Code",
		dir:            ".claude",
		file:           "settings.json",
		invocation:     "fence hook claude-code",
		preMatcher:     toolMatcher,
		sessionMatcher: sessionStartMatcher,
	},
	{
		name:           "codex",
		display:        "Codex",
		dir:            ".codex",
		file:           "hooks.json",
		invocation:     "fence hook codex",
		preMatcher:     codexToolMatcher,
		sessionMatcher: sessionStartMatcher,
		trustNote:      "Codex only runs hooks you've trusted: run /hooks inside Codex to review and trust them.",
	},
}

// resolveAgent maps the optional positional argument of init/uninstall to an
// agent target; no argument means the first adapter, claude-code.
func resolveAgent(args []string) (hookAgent, error) {
	if len(args) == 0 {
		return hookAgents[0], nil
	}
	var names []string
	for _, a := range hookAgents {
		if a.name == args[0] {
			return a, nil
		}
		names = append(names, a.name)
	}
	return hookAgent{}, fmt.Errorf("unknown agent %q (supported: %s)", args[0], strings.Join(names, ", "))
}

func newInitCommand() *cobra.Command {
	var (
		global bool
		quiet  bool
	)

	cmd := &cobra.Command{
		Use:   "init [agent]",
		Short: "Install the Fence hooks into an agent's settings",
		Long: "Adds two hooks to an agent's settings: a PreToolUse hook so Fence\n" +
			"inspects each tool call, and a SessionStart hook that shows a banner\n" +
			"confirming the session is guarded. The agent is claude-code (default)\n" +
			"or codex. By default it writes the project settings (./.claude or\n" +
			"./.codex); use --global for the user-level file under ~.\n\n" +
			"The change is idempotent and preserves any existing settings. Re-running\n" +
			"init always converges the hook commands, so it also heals a stale binary\n" +
			"path and toggles --quiet on or off.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := initSupportedOS(runtime.GOOS); err != nil {
				return fail(cmd, err)
			}
			agent, err := resolveAgent(args)
			if err != nil {
				return fail(cmd, err)
			}
			path, err := settingsPath(agent, global)
			if err != nil {
				return fail(cmd, err)
			}
			result, err := installHooks(path, desiredHooks(agent, quiet))
			if err != nil {
				return fail(cmd, err)
			}
			switch result {
			case hookInstalled:
				fmt.Fprintf(cmd.OutOrStdout(), "Installed the Fence hooks in %s\n", path)
				fmt.Fprintf(cmd.OutOrStdout(), "Restart %s (or start a new session) to activate them.\n", agent.display)
			case hookUpdated:
				fmt.Fprintf(cmd.OutOrStdout(), "Updated the Fence hook commands in %s\n", path)
				fmt.Fprintf(cmd.OutOrStdout(), "Restart %s (or start a new session) to pick them up.\n", agent.display)
			default:
				fmt.Fprintf(cmd.OutOrStdout(), "Fence hooks already present in %s\n", path)
			}
			if agent.trustNote != "" && result != hookUnchanged {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\n", agent.trustNote)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&global, "global", false, "install into ~/.claude/settings.json instead of the project")
	cmd.Flags().BoolVar(&quiet, "quiet", false,
		"don't show a chat notice for allowed tool calls (re-run init without it to switch back)")
	// --verbose asked for what is now the default; running it plain is correct.
	cmd.Flags().Bool("verbose", true, "")
	_ = cmd.Flags().MarkDeprecated("verbose",
		"allowed-call notices are now the default; use --quiet to turn them off")
	return cmd
}

// initSupportedOS refuses to install hooks where the hook path has never been
// verified end to end — a silently broken hook is worse than an honest no.
// Uninstall carries no such guard: removing hooks is always safe.
func initSupportedOS(goos string) error {
	if goos == "windows" {
		return fmt.Errorf("native Windows isn't supported yet (the hook path is unverified there, and a silently broken hook is worse than an honest no) — " +
			"run Fence inside WSL, where it works exactly as on Linux, or follow https://github.com/hoophq/fence/issues/26")
	}
	return nil
}

func settingsPath(agent hookAgent, global bool) (string, error) {
	base, err := os.Getwd()
	if global {
		base, err = os.UserHomeDir()
	}
	if err != nil {
		return "", err
	}
	return filepath.Join(base, agent.dir, agent.file), nil
}

// hookSpec is one hook entry Fence wants present in the settings: the event to
// hook, the matcher for new installs (an existing entry's matcher is never
// touched — the user may have narrowed it), the exact command to run, and the
// bare invocation that identifies an entry as ours.
type hookSpec struct {
	event      string
	matcher    string
	command    string
	invocation string
}

// desiredHooks returns the hook entries `fence init` converges the settings to.
func desiredHooks(agent hookAgent, quiet bool) []hookSpec {
	base := hookInvocation(agent)
	pre := base
	if quiet {
		pre += " --quiet"
	}
	return []hookSpec{
		{event: "PreToolUse", matcher: agent.preMatcher, command: pre, invocation: agent.invocation},
		{event: "SessionStart", matcher: agent.sessionMatcher, command: base + " session-start", invocation: agent.invocation},
	}
}

// hookInvocation returns the command string the agent should run. It uses the
// absolute path of the current binary so the hook works regardless of PATH, but
// keeps symlinks unresolved: package managers point a stable symlink (e.g.
// /opt/homebrew/bin/fence) at a version-pinned target that vanishes on upgrade,
// so resolving it would break the hook at the next `brew upgrade`.
func hookInvocation(agent hookAgent) string {
	exe, err := os.Executable()
	if err != nil {
		return agent.invocation // fall back to PATH lookup of "fence"
	}
	return fmt.Sprintf("%s hook %s", exe, agent.name)
}

// hookInstallResult describes what installHooks changed. Higher values are
// more newsworthy: an install (a hook that wasn't there before) outranks an
// update (a command healed in place).
type hookInstallResult int

const (
	hookUnchanged hookInstallResult = iota
	hookUpdated
	hookInstalled
)

// installHooks merges the desired hook entries into the settings file at path,
// creating it if necessary. An existing fence hook whose command differs —
// e.g. a stale binary path left by a previous install, or a quiet toggle —
// is updated in place, so re-running `fence init` always converges on working
// hooks.
func installHooks(path string, specs []hookSpec) (hookInstallResult, error) {
	settings := map[string]any{}
	if data, err := os.ReadFile(path); err == nil {
		if len(data) > 0 {
			if err := json.Unmarshal(data, &settings); err != nil {
				return hookUnchanged, fmt.Errorf("%s is not valid JSON: %w", path, err)
			}
		}
	} else if !os.IsNotExist(err) {
		return hookUnchanged, err
	}

	hooks := asMap(settings["hooks"])

	result := hookUnchanged
	for _, spec := range specs {
		entries := asSlice(hooks[spec.event])
		found := false
		for _, e := range entries {
			for _, h := range asSlice(asMap(e)["hooks"]) {
				hm := asMap(h)
				cmd, ok := hm["command"].(string)
				if !ok || !containsHook(cmd, spec.invocation) {
					continue
				}
				found = true
				if want := convergeCommand(cmd, spec.command, spec.invocation); cmd != want {
					hm["command"] = want
					result = max(result, hookUpdated)
				}
			}
		}
		if !found {
			entries = append(entries, map[string]any{
				"matcher": spec.matcher,
				"hooks": []any{
					map[string]any{"type": "command", "command": spec.command},
				},
			})
			hooks[spec.event] = entries
			result = hookInstalled
		}
	}

	if result == hookUnchanged {
		return hookUnchanged, nil
	}
	settings["hooks"] = hooks

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return hookUnchanged, err
	}
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return hookUnchanged, err
	}
	out = append(out, '\n')
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return hookUnchanged, err
	}
	return result, nil
}

// convergeCommand rewrites an existing Fence hook command to the desired
// invocation while keeping any trailing tokens init does not manage (a
// hand-added --rules, say): the user put them there, and dropping them would
// silently weaken their setup. The tokens init owns — the session-start
// subcommand, --quiet, and the legacy --verbose (now the default, so the
// token is dropped) — are regenerated from the desired command.
func convergeCommand(existing, desired, invocation string) string {
	_, rest, found := strings.Cut(existing, invocation)
	if !found {
		return desired
	}
	var extra []string
	for tok := range strings.FieldsSeq(rest) {
		if tok == "session-start" || tok == "--quiet" || tok == "--verbose" {
			continue
		}
		extra = append(extra, tok)
	}
	if len(extra) == 0 {
		return desired
	}
	return desired + " " + strings.Join(extra, " ")
}

// containsHook reports whether cmd is a Fence hook invocation for the given
// agent (e.g. "fence hook claude-code") — through any binary path, possibly
// followed by a subcommand or flags ("… session-start", "… --quiet").
// Trailing shell syntax means the string only mentions the invocation rather
// than being one, so it is not ours.
func containsHook(cmd, invocation string) bool {
	_, rest, found := strings.Cut(cmd, invocation)
	if !found {
		return false
	}
	if rest == "" {
		return true
	}
	if rest[0] != ' ' {
		return false // e.g. "fence hook claude-codex" vs "fence hook claude-code"
	}
	for tok := range strings.FieldsSeq(rest) {
		if strings.ContainsAny(tok, "|&;<>()`$\"'\\") {
			return false
		}
	}
	return true
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func asSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}
