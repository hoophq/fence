package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const hookCommand = "leash hook claude-code"

// toolMatcher is the Claude Code tool-name regexp Leash hooks into: the tools
// whose actions the engine actually evaluates.
const toolMatcher = "Bash|Write|Edit|MultiEdit|NotebookEdit|WebFetch"

func newInitCommand() *cobra.Command {
	var global bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Install the Leash hook into Claude Code settings",
		Long: "Adds a PreToolUse hook to your Claude Code settings so Leash inspects\n" +
			"each tool call. By default it writes the project settings\n" +
			"(./.claude/settings.json); use --global for ~/.claude/settings.json.\n\n" +
			"The change is idempotent and preserves any existing settings.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := settingsPath(global)
			if err != nil {
				return fail(cmd, err)
			}
			binary, err := hookInvocation()
			if err != nil {
				return fail(cmd, err)
			}
			changed, err := installHook(path, binary)
			if err != nil {
				return fail(cmd, err)
			}
			if changed {
				fmt.Fprintf(cmd.OutOrStdout(), "Installed Leash hook in %s\n", path)
				fmt.Fprintf(cmd.OutOrStdout(), "Restart Claude Code (or start a new session) to activate it.\n")
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Leash hook already present in %s\n", path)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&global, "global", false, "install into ~/.claude/settings.json instead of the project")
	return cmd
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

// hookInvocation returns the command string Claude Code should run. It uses the
// absolute path of the current binary so the hook works regardless of PATH.
func hookInvocation() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return hookCommand, nil // fall back to PATH lookup of "leash"
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		resolved = exe
	}
	return fmt.Sprintf("%s hook claude-code", resolved), nil
}

// installHook merges a PreToolUse hook into the settings file at path, creating
// it if necessary. It returns whether a change was made.
func installHook(path, command string) (bool, error) {
	settings := map[string]any{}
	if data, err := os.ReadFile(path); err == nil {
		if len(data) > 0 {
			if err := json.Unmarshal(data, &settings); err != nil {
				return false, fmt.Errorf("%s is not valid JSON: %w", path, err)
			}
		}
	} else if !os.IsNotExist(err) {
		return false, err
	}

	hooks := asMap(settings["hooks"])
	preToolUse := asSlice(hooks["PreToolUse"])

	if hookPresent(preToolUse) {
		return false, nil
	}

	entry := map[string]any{
		"matcher": toolMatcher,
		"hooks": []any{
			map[string]any{"type": "command", "command": command},
		},
	}
	preToolUse = append(preToolUse, entry)
	hooks["PreToolUse"] = preToolUse
	settings["hooks"] = hooks

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return false, err
	}
	out = append(out, '\n')
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// hookPresent reports whether any PreToolUse entry already runs a leash hook.
func hookPresent(entries []any) bool {
	for _, e := range entries {
		em := asMap(e)
		for _, h := range asSlice(em["hooks"]) {
			hm := asMap(h)
			if cmd, ok := hm["command"].(string); ok && containsHook(cmd) {
				return true
			}
		}
	}
	return false
}

func containsHook(cmd string) bool {
	return len(cmd) >= len(hookCommand) && (cmd == hookCommand ||
		// match "<path>/leash hook claude-code" too
		hasSuffix(cmd, hookCommand))
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
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
