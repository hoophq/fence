package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Claude Code plugins can contribute PreToolUse hooks of their own, so a
// machine can already be guarded before `fence init` ever runs — the hoop
// plugin ships exactly such a hook. Installing ours on top makes Fence
// evaluate every tool call twice: same verdict, doubled latency and doubled
// chat notices. These helpers let init see that hook and stand down.
//
// Only Claude Code has this problem. Codex hooks live in the user's own
// .codex/hooks.json with no plugin layer, and OpenCode's shim plugin is a file
// Fence generates and owns outright.

// pluginHookProvider is a plugin that already registers a Fence hook: who it
// is, and the hooks file that proves it.
type pluginHookProvider struct {
	name   string // "hoop@hooplabs", as the user sees it in enabledPlugins
	source string // the hooks.json that declares the hook
}

// installedPlugins is the shape of ~/.claude/plugins/installed_plugins.json
// that we depend on. Everything else in that file is ignored, so Claude Code
// can grow the format without breaking detection.
type installedPlugins struct {
	Plugins map[string][]struct {
		InstallPath string `json:"installPath"`
	} `json:"plugins"`
}

// findPluginHookProvider reports the enabled Claude Code plugin that already
// provides a Fence PreToolUse hook, if any.
//
// Detection is deliberately conservative, because the two ways to be wrong are
// not equally bad. A false negative installs a hook that duplicates the
// plugin's: noisy, but the user stays guarded. A false positive makes init
// skip the hook when nothing else provides it, leaving the user unguarded
// while init reports success — the one outcome Fence must never produce. So a
// provider is only reported on positive evidence that the plugin invokes this
// agent's Fence hook, and every uncertainty (unreadable file, unparseable
// JSON, plugin not explicitly enabled) resolves to "no provider".
//
// enabled carries the settings scopes that decide whether a plugin is on, most
// specific last.
func findPluginHookProvider(agent hookAgent, enabled ...map[string]any) (pluginHookProvider, bool) {
	if !agent.pluginHooks {
		return pluginHookProvider{}, false
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return pluginHookProvider{}, false
	}
	root := filepath.Join(home, ".claude", "plugins")
	data, err := os.ReadFile(filepath.Join(root, "installed_plugins.json"))
	if err != nil {
		return pluginHookProvider{}, false
	}
	var installed installedPlugins
	if json.Unmarshal(data, &installed) != nil {
		return pluginHookProvider{}, false
	}

	for name, installs := range installed.Plugins {
		if !pluginEnabled(name, enabled...) {
			continue
		}
		for _, install := range installs {
			if install.InstallPath == "" {
				continue
			}
			hooksFile := filepath.Join(install.InstallPath, "hooks", "hooks.json")
			if pluginDeclaresHook(hooksFile, install.InstallPath, agent) {
				return pluginHookProvider{name: name, source: hooksFile}, true
			}
		}
	}
	return pluginHookProvider{}, false
}

// pluginEnabled reports whether a plugin is switched on. Absence is not
// enablement: a plugin present in installed_plugins.json but never listed in
// enabledPlugins contributes no hooks, so treating it as a provider would
// disarm the user. Later scopes win, so a project can turn off what the user
// level turned on.
func pluginEnabled(name string, scopes ...map[string]any) bool {
	on := false
	for _, scope := range scopes {
		if v, ok := asMap(scope["enabledPlugins"])[name].(bool); ok {
			on = v
		}
	}
	return on
}

// pluginDeclaresHook reports whether the plugin's hooks file registers a
// PreToolUse hook that runs Fence for this agent.
//
// Two shapes count. A plugin may invoke Fence directly, which containsHook
// recognizes exactly as it does in settings. More often it goes through a
// wrapper script under ${CLAUDE_PLUGIN_ROOT} — the hoop plugin's fence-hook.sh
// resolves the binary from PATH and fails open when it is missing — and then
// the command names a script, not Fence. For that case we expand the plugin
// root and read the script itself, so the evidence is still Fence being
// invoked rather than a filename that merely looks right.
func pluginDeclaresHook(hooksFile, pluginRoot string, agent hookAgent) bool {
	data, err := os.ReadFile(hooksFile)
	if err != nil {
		return false
	}
	var declared struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if json.Unmarshal(data, &declared) != nil {
		return false
	}
	for _, entry := range declared.Hooks["PreToolUse"] {
		for _, h := range entry.Hooks {
			if containsHook(h.Command, agent.invocation) {
				return true
			}
			if script, ok := pluginScriptPath(h.Command, pluginRoot); ok && scriptRunsFence(script, agent) {
				return true
			}
		}
	}
	return false
}

// pluginScriptPath resolves the script a plugin hook command runs, when that
// command is a plain invocation of a file inside the plugin. Anything with
// shell syntax in it is left alone: we would be guessing at what actually runs,
// and guessing is what disarms people.
func pluginScriptPath(command, pluginRoot string) (string, bool) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return "", false
	}
	path := fields[0]
	if strings.ContainsAny(command, "|&;<>()`\"'\\") {
		return "", false
	}
	path = strings.ReplaceAll(path, "${CLAUDE_PLUGIN_ROOT}", pluginRoot)
	path = strings.ReplaceAll(path, "$CLAUDE_PLUGIN_ROOT", pluginRoot)
	if !filepath.IsAbs(path) {
		return "", false
	}
	// Only trust scripts the plugin ships. A hook pointing somewhere else is
	// outside what this plugin can vouch for.
	if rel, err := filepath.Rel(pluginRoot, path); err != nil || strings.HasPrefix(rel, "..") {
		return "", false
	}
	return path, true
}

// scriptRunsFence reports whether a plugin's wrapper script invokes Fence's
// hook for this agent. The binary reaches the script through a variable
// ("$FENCE" hook claude-code), so containsHook cannot be reused — it keys on
// the whole invocation including the binary. We require both halves of the
// evidence: the agent-specific "hook <agent>" subcommand, and Fence named
// somewhere in the script. Wrapper scripts are small; a size cap keeps a
// pathological file from being read into memory.
func scriptRunsFence(path string, agent hookAgent) bool {
	info, err := os.Stat(path)
	if err != nil || info.Size() > 64*1024 {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	body := string(data)
	return strings.Contains(body, "hook "+agent.name) && strings.Contains(strings.ToLower(body), "fence")
}
