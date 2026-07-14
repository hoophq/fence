package cli

import (
	"fmt"
	"os"
	"path/filepath"
)

// installStatusLineHooks converges the settings of an agent that announces
// Fence through a status line (Claude Code): the PreToolUse spec always, plus
// Fence's statusLine entry — running slCommand — when the slot is free or
// already ours, removing the legacy SessionStart banner hook the status line
// replaces. When another status line is configured, in this file or a scope
// that interacts with it, Fence leaves it untouched and falls back to the
// SessionStart banner spec; the returned note tells the user why.
func installStatusLineHooks(path string, agent hookAgent, specs []hookSpec, slCommand string, global bool) (hookInstallResult, string, error) {
	settings, err := loadSettings(path)
	if err != nil {
		return hookUnchanged, "", err
	}

	pre, session := specs[0], specs[1]

	if takenAt, taken := statusLineTaken(path, settings, global, agent.invocation); taken {
		result := convergeHooks(settings, []hookSpec{pre, session})
		note := fmt.Sprintf("A status line is already configured (%s) — left untouched; the session banner announces Fence instead.\n"+
			"To show Fence there too, have your statusline command append the output of `%s statusline`.",
			takenAt, agent.invocation)
		if result == hookUnchanged {
			return hookUnchanged, note, nil
		}
		return result, note, saveSettings(path, settings)
	}

	result := convergeHooks(settings, []hookSpec{pre})
	result = max(result, convergeStatusLine(settings, agent.invocation, slCommand))
	// The status line replaces the banner-era SessionStart hook: converge
	// installs from before it existed by removing theirs. The hooks map can't
	// empty out here — the PreToolUse entry was just converged into it.
	if removeEventHooks(asMap(settings["hooks"]), "SessionStart", agent.invocation) {
		result = max(result, hookUpdated)
	}

	if result == hookUnchanged {
		return hookUnchanged, "", nil
	}
	return result, "", saveSettings(path, settings)
}

// convergeStatusLine points the settings' statusLine entry at command.
// Fence's own entry is converged in place — keys the user added to it
// (padding, say) survive, and unmanaged trailing tokens ride along exactly as
// for hook commands. The caller has already established the slot is not
// someone else's.
func convergeStatusLine(settings map[string]any, invocation, command string) hookInstallResult {
	sl := asMap(settings["statusLine"])
	if existing, ok := sl["command"].(string); ok && containsHook(existing, invocation) {
		want := convergeCommand(existing, command, invocation)
		if existing == want {
			return hookUnchanged
		}
		sl["command"] = want
		return hookUpdated
	}
	settings["statusLine"] = map[string]any{"type": "command", "command": command}
	return hookInstalled
}

// statusLineTaken reports whether a status line that is not Fence's already
// governs sessions this install would cover, and where. Beyond the target
// settings themselves, a project install checks the scopes it interacts with:
// the user-level settings a project statusLine would silently shadow, and the
// project-local file that would shadow ours. Occupying the slot in either
// case clobbers the user's setup in effect, if not in bytes.
func statusLineTaken(path string, settings map[string]any, global bool, invocation string) (string, bool) {
	if foreignStatusLine(settings, invocation) {
		return path, true
	}
	if global {
		return "", false
	}
	var others []string
	if home, err := os.UserHomeDir(); err == nil {
		others = append(others, filepath.Join(home, ".claude", "settings.json"))
	}
	others = append(others, filepath.Join(filepath.Dir(path), "settings.local.json"))
	for _, other := range others {
		if other == path {
			continue
		}
		otherSettings, err := loadSettings(other)
		if err != nil {
			// An unreadable scope shouldn't block the install, but say so:
			// a status line hiding in a file we couldn't read would get
			// shadowed without warning.
			fmt.Fprintf(os.Stderr, "fence: checking %s for a status line: %v (assuming none)\n", other, err)
			continue
		}
		if foreignStatusLine(otherSettings, invocation) {
			return other, true
		}
	}
	return "", false
}

// foreignStatusLine reports whether settings carry a status line that is not
// Fence's own. Any statusLine shape not positively recognized as ours counts:
// the slot belongs to the user.
func foreignStatusLine(settings map[string]any, invocation string) bool {
	sl, present := settings["statusLine"]
	if !present {
		return false
	}
	cmd, ok := asMap(sl)["command"].(string)
	return !ok || !containsHook(cmd, invocation)
}
