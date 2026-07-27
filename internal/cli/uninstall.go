package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newUninstallCommand() *cobra.Command {
	var (
		global    bool
		hooksOnly bool
	)

	cmd := &cobra.Command{
		Use:   "uninstall [agent]",
		Short: "Remove the Fence hooks from an agent's settings",
		Long: "The exit door: removes everything `fence init` installed from an agent's\n" +
			"settings — the hooks and Fence's status line — leaving everything else\n" +
			"in the file untouched. The agent is claude-code (default), codex, or\n" +
			"opencode (whose generated plugin file is deleted instead). By default it\n" +
			"edits the project settings (./.claude, ./.codex or ./.opencode); use\n" +
			"--global for the user-level file under ~.\n\n" +
			"Use --hooks-only to remove just the hooks and keep Fence's status line —\n" +
			"what you want when a plugin runs the hook, since no plugin can provide a\n" +
			"status line.\n\n" +
			"Rulepacks installed with `fence add` are not touched — remove those with\n" +
			"`fence remove <pack>`.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			agent, err := resolveAgent(args)
			if err != nil {
				return fail(cmd, err)
			}
			if hooksOnly && agent.plugin {
				return fail(cmd, fmt.Errorf("--hooks-only doesn't apply to %s: its hooks and banner live in one generated plugin file", agent.display))
			}
			var path string
			var result hookRemoveResult
			if agent.plugin {
				if path, err = opencodePluginPath(global); err == nil {
					result, err = removeOpencodePlugin(path)
				}
			} else {
				if path, err = settingsPath(agent, global); err == nil {
					result, err = removeHooks(path, agent.invocation, hooksOnly)
				}
			}
			if err != nil {
				return fail(cmd, err)
			}
			what := "hooks"
			switch {
			case agent.plugin:
				what = "plugin"
			case hooksOnly:
				what = "hooks (status line kept)"
			}
			switch result {
			case hookRemoved:
				fmt.Fprintf(cmd.OutOrStdout(), "Removed the Fence %s from %s\n", what, path)
				fmt.Fprintf(cmd.OutOrStdout(), "Restart %s (or start a new session) for the change to take effect.\n", agent.display)
			default:
				fmt.Fprintf(cmd.OutOrStdout(), "No Fence %s found in %s\n", what, path)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&global, "global", false, "remove from the user-level settings under ~ instead of the project")
	cmd.Flags().BoolVar(&hooksOnly, "hooks-only", false, "remove the hooks but keep Fence's status line")
	return cmd
}

// hookRemoveResult describes what removeHooks changed.
type hookRemoveResult int

const (
	hookAbsent hookRemoveResult = iota
	hookRemoved
)

// removeHooks deletes exactly the Fence entries for one agent from the
// settings file at path — the hook commands and a Fence-owned statusLine,
// recognized the same way init converges them, via containsHook, so a stale
// binary path, a hand-added flag, or a user-narrowed matcher all still count
// as ours. Containers that held only Fence entries are removed too (an entry
// whose hooks list empties, an event whose entries empty, the hooks key
// itself), so init followed by uninstall leaves the settings as they were.
// Everything else is preserved — a status line that is not Fence's above all
// — and when there is nothing to remove the file is not rewritten, or created.
//
// hooksOnly keeps Fence's own status line in place. The two are separable
// because they can have different owners: a plugin can run the hook, but
// statusLine is a settings-only field no plugin can declare, so removing a
// duplicate hook must not cost the user their status line.
func removeHooks(path, invocation string, hooksOnly bool) (hookRemoveResult, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return hookAbsent, nil
	}
	settings, err := loadSettings(path)
	if err != nil {
		return hookAbsent, err
	}

	hooks := asMap(settings["hooks"])
	removed := false
	for _, event := range []string{"PreToolUse", "SessionStart"} {
		removed = removeEventHooks(hooks, event, invocation) || removed
	}
	if removed && len(hooks) == 0 {
		delete(settings, "hooks")
	}

	if !hooksOnly {
		if cmd, ok := asMap(settings["statusLine"])["command"].(string); ok && containsHook(cmd, invocation) {
			delete(settings, "statusLine")
			removed = true
		}
	}

	if !removed {
		return hookAbsent, nil
	}
	if err := saveSettings(path, settings); err != nil {
		return hookAbsent, err
	}
	return hookRemoved, nil
}

// removeEventHooks deletes the Fence hook commands under one event of a
// settings hooks map, pruning containers that held only Fence entries, and
// reports whether it removed anything.
func removeEventHooks(hooks map[string]any, event, invocation string) bool {
	entries := asSlice(hooks[event])
	if entries == nil {
		return false
	}
	removed := false
	keptEntries := make([]any, 0, len(entries))
	for _, e := range entries {
		em := asMap(e)
		inner := asSlice(em["hooks"])
		keptInner := make([]any, 0, len(inner))
		for _, h := range inner {
			if cmd, ok := asMap(h)["command"].(string); ok && containsHook(cmd, invocation) {
				removed = true
				continue
			}
			keptInner = append(keptInner, h)
		}
		if len(keptInner) == 0 && len(inner) > 0 {
			continue // the entry existed only to hold Fence hooks
		}
		if len(keptInner) < len(inner) {
			em["hooks"] = keptInner
		}
		keptEntries = append(keptEntries, e)
	}
	if !removed {
		return false
	}
	if len(keptEntries) == 0 {
		delete(hooks, event)
	} else {
		hooks[event] = keptEntries
	}
	return true
}
