package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newUninstallCommand() *cobra.Command {
	var global bool

	cmd := &cobra.Command{
		Use:   "uninstall [agent]",
		Short: "Remove the Fence hooks from an agent's settings",
		Long: "The exit door: removes the hooks `fence init` installed from an agent's\n" +
			"settings, leaving everything else in the file untouched. The agent is\n" +
			"claude-code (default), codex, or opencode (whose generated plugin file\n" +
			"is deleted instead). By default it edits the project settings (./.claude,\n" +
			"./.codex or ./.opencode); use --global for the user-level file under ~.\n\n" +
			"Rulepacks installed with `fence add` are not touched — remove those with\n" +
			"`fence remove <pack>`.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			agent, err := resolveAgent(args)
			if err != nil {
				return fail(cmd, err)
			}
			var path string
			var result hookRemoveResult
			if agent.plugin {
				if path, err = opencodePluginPath(global); err == nil {
					result, err = removeOpencodePlugin(path)
				}
			} else {
				if path, err = settingsPath(agent, global); err == nil {
					result, err = removeHooks(path, agent.invocation)
				}
			}
			if err != nil {
				return fail(cmd, err)
			}
			what := "hooks"
			if agent.plugin {
				what = "plugin"
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
	return cmd
}

// hookRemoveResult describes what removeHooks changed.
type hookRemoveResult int

const (
	hookAbsent hookRemoveResult = iota
	hookRemoved
)

// removeHooks deletes exactly the Fence hook commands for one agent from the
// settings file at path — recognized the same way init converges them, via
// containsHook, so a stale binary path, a hand-added flag, or a user-narrowed
// matcher all still count as ours. Containers that held only Fence entries
// are removed too (an entry whose hooks list empties, an event whose entries
// empty, the hooks key itself), so init followed by uninstall leaves the
// settings as they were. Everything else is preserved, and when there is
// nothing to remove the file is not rewritten — or created.
func removeHooks(path, invocation string) (hookRemoveResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return hookAbsent, nil
		}
		return hookAbsent, err
	}
	if len(data) == 0 {
		return hookAbsent, nil
	}
	settings := map[string]any{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return hookAbsent, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}

	hooks := asMap(settings["hooks"])
	removed := false
	for _, event := range []string{"PreToolUse", "SessionStart"} {
		entries := asSlice(hooks[event])
		if entries == nil {
			continue
		}
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
		if len(keptEntries) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = keptEntries
		}
	}

	if !removed {
		return hookAbsent, nil
	}
	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		settings["hooks"] = hooks
	}

	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return hookAbsent, err
	}
	out = append(out, '\n')
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return hookAbsent, err
	}
	return hookRemoved, nil
}
