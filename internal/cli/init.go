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

const hookCommand = "leash hook claude-code"

// toolMatcher is the Claude Code tool-name regexp Leash hooks into: the tools
// whose actions the engine actually evaluates.
const toolMatcher = "Bash|Write|Edit|MultiEdit|NotebookEdit|WebFetch"

// sessionStartMatcher fires the banner when a session begins or is cleared,
// but not after every context compaction.
const sessionStartMatcher = "startup|resume|clear"

func newInitCommand() *cobra.Command {
	var (
		global bool
		quiet  bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Install the Leash hooks into Claude Code settings",
		Long: "Adds two hooks to your Claude Code settings: a PreToolUse hook so Leash\n" +
			"inspects each tool call, and a SessionStart hook that shows a banner\n" +
			"confirming the session is guarded. By default it writes the project\n" +
			"settings (./.claude/settings.json); use --global for ~/.claude/settings.json.\n\n" +
			"The change is idempotent and preserves any existing settings. Re-running\n" +
			"init always converges the hook commands, so it also heals a stale binary\n" +
			"path and toggles --quiet on or off.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := initSupportedOS(runtime.GOOS); err != nil {
				return fail(cmd, err)
			}
			path, err := settingsPath(global)
			if err != nil {
				return fail(cmd, err)
			}
			result, err := installHooks(path, desiredHooks(quiet))
			if err != nil {
				return fail(cmd, err)
			}
			switch result {
			case hookInstalled:
				fmt.Fprintf(cmd.OutOrStdout(), "Installed the Leash hooks in %s\n", path)
				fmt.Fprintf(cmd.OutOrStdout(), "Restart Claude Code (or start a new session) to activate them.\n")
			case hookUpdated:
				fmt.Fprintf(cmd.OutOrStdout(), "Updated the Leash hook commands in %s\n", path)
				fmt.Fprintf(cmd.OutOrStdout(), "Restart Claude Code (or start a new session) to pick them up.\n")
			default:
				fmt.Fprintf(cmd.OutOrStdout(), "Leash hooks already present in %s\n", path)
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
			"run Leash inside WSL, where it works exactly as on Linux, or follow https://github.com/hoophq/leash/issues/26")
	}
	return nil
}

func settingsPath(global bool) (string, error) {
	if global {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".claude", "settings.json"), nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(wd, ".claude", "settings.json"), nil
}

// hookSpec is one hook entry Leash wants present in the settings: the event to
// hook, the matcher for new installs (an existing entry's matcher is never
// touched — the user may have narrowed it), and the exact command to run.
type hookSpec struct {
	event   string
	matcher string
	command string
}

// desiredHooks returns the hook entries `leash init` converges the settings to.
func desiredHooks(quiet bool) []hookSpec {
	base := hookInvocation()
	pre := base
	if quiet {
		pre += " --quiet"
	}
	return []hookSpec{
		{event: "PreToolUse", matcher: toolMatcher, command: pre},
		{event: "SessionStart", matcher: sessionStartMatcher, command: base + " session-start"},
	}
}

// hookInvocation returns the command string Claude Code should run. It uses the
// absolute path of the current binary so the hook works regardless of PATH, but
// keeps symlinks unresolved: package managers point a stable symlink (e.g.
// /opt/homebrew/bin/leash) at a version-pinned target that vanishes on upgrade,
// so resolving it would break the hook at the next `brew upgrade`.
func hookInvocation() string {
	exe, err := os.Executable()
	if err != nil {
		return hookCommand // fall back to PATH lookup of "leash"
	}
	return fmt.Sprintf("%s hook claude-code", exe)
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
// creating it if necessary. An existing leash hook whose command differs —
// e.g. a stale binary path left by a previous install, or a quiet toggle —
// is updated in place, so re-running `leash init` always converges on working
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
				if !ok || !containsHook(cmd) {
					continue
				}
				found = true
				if want := convergeCommand(cmd, spec.command); cmd != want {
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

// convergeCommand rewrites an existing Leash hook command to the desired
// invocation while keeping any trailing tokens init does not manage (a
// hand-added --rules, say): the user put them there, and dropping them would
// silently weaken their setup. The tokens init owns — the session-start
// subcommand, --quiet, and the legacy --verbose (now the default, so the
// token is dropped) — are regenerated from the desired command.
func convergeCommand(existing, desired string) string {
	_, rest, found := strings.Cut(existing, hookCommand)
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

// containsHook reports whether cmd is a Leash claude-code hook invocation —
// through any binary path, possibly followed by a subcommand or flags
// ("… session-start", "… --quiet"). Trailing shell syntax means the string
// only mentions the invocation rather than being one, so it is not ours.
func containsHook(cmd string) bool {
	_, rest, found := strings.Cut(cmd, hookCommand)
	if !found {
		return false
	}
	if rest == "" {
		return true
	}
	if rest[0] != ' ' {
		return false // e.g. "leash hook claude-codex"
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
