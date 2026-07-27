package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The wrapper the hoop plugin actually ships, trimmed to the parts detection
// keys on: Fence resolved into a variable, then invoked with the agent's hook
// subcommand. The binary never appears literally, which is why containsHook
// alone cannot recognize this.
const wrapperScript = `#!/bin/sh
FENCE="${HOOP_FENCE_BIN:-}"
if [ -z "$FENCE" ]; then
  FENCE="$(command -v fence 2>/dev/null)"
fi
exec "$FENCE" hook claude-code "$@"
`

// A sibling plugin hook that rewrites commands for a different tool. It is a
// PreToolUse hook in the same file and must never read as Fence.
const foreignScript = `#!/bin/sh
# runs before fence does, but is not fence
exec "$JULIUS" hook claude pre
`

type pluginFixture struct {
	name    string // key in installed_plugins.json and enabledPlugins
	hooks   string // hooks/hooks.json contents; "" writes no file
	script  string // scripts/hook.sh contents; "" writes no file
	noEntry bool   // omit from installed_plugins.json entirely
}

// writePluginHome builds a fake ~/.claude/plugins tree and points HOME at it.
func writePluginHome(t *testing.T, fixtures ...pluginFixture) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := filepath.Join(home, ".claude", "plugins")

	installed := installedPlugins{Plugins: map[string][]struct {
		InstallPath string `json:"installPath"`
	}{}}
	for _, f := range fixtures {
		dir := filepath.Join(root, "cache", f.name, "1.0.0")
		if f.hooks != "" {
			writeTestFile(t, filepath.Join(dir, "hooks", "hooks.json"), f.hooks)
		}
		if f.script != "" {
			writeTestFile(t, filepath.Join(dir, "scripts", "hook.sh"), f.script)
		}
		if f.noEntry {
			continue
		}
		installed.Plugins[f.name] = []struct {
			InstallPath string `json:"installPath"`
		}{{InstallPath: dir}}
	}
	data, err := json.Marshal(installed)
	if err != nil {
		t.Fatalf("marshal installed_plugins: %v", err)
	}
	writeTestFile(t, filepath.Join(root, "installed_plugins.json"), string(data))
}

// preToolUse builds a hooks.json declaring one PreToolUse command.
func preToolUse(command string) string {
	return `{"hooks":{"PreToolUse":[{"matcher":"` + toolMatcher +
		`","hooks":[{"type":"command","command":"` + command + `"}]}]}}`
}

func enabledScope(name string, on bool) map[string]any {
	return map[string]any{"enabledPlugins": map[string]any{name: on}}
}

func TestFindPluginHookProvider(t *testing.T) {
	const plugin = "hoop@hooplabs"
	const wrapperCmd = "${CLAUDE_PLUGIN_ROOT}/scripts/hook.sh"

	tests := []struct {
		name    string
		fixture pluginFixture
		scopes  []map[string]any
		agent   hookAgent
		want    bool
	}{
		{
			// The case that shipped the bug: a wrapper script, invoked through
			// the plugin root, that execs Fence.
			name:    "wrapper script running fence",
			fixture: pluginFixture{name: plugin, hooks: preToolUse(wrapperCmd), script: wrapperScript},
			scopes:  []map[string]any{enabledScope(plugin, true)},
			want:    true,
		},
		{
			name:    "plugin invoking fence directly",
			fixture: pluginFixture{name: plugin, hooks: preToolUse("/opt/homebrew/bin/fence hook claude-code")},
			scopes:  []map[string]any{enabledScope(plugin, true)},
			want:    true,
		},
		{
			name:    "quiet flag on a direct invocation still counts",
			fixture: pluginFixture{name: plugin, hooks: preToolUse("fence hook claude-code --quiet")},
			scopes:  []map[string]any{enabledScope(plugin, true)},
			want:    true,
		},
		// Everything below must NOT report a provider: a false positive makes
		// init skip the hook and leaves the user unguarded.
		{
			name:    "plugin explicitly disabled",
			fixture: pluginFixture{name: plugin, hooks: preToolUse(wrapperCmd), script: wrapperScript},
			scopes:  []map[string]any{enabledScope(plugin, false)},
			want:    false,
		},
		{
			name:    "plugin never enabled",
			fixture: pluginFixture{name: plugin, hooks: preToolUse(wrapperCmd), script: wrapperScript},
			scopes:  nil,
			want:    false,
		},
		{
			// A project scope turning the plugin off wins over the user scope.
			name:    "disabled by the more specific scope",
			fixture: pluginFixture{name: plugin, hooks: preToolUse(wrapperCmd), script: wrapperScript},
			scopes:  []map[string]any{enabledScope(plugin, true), enabledScope(plugin, false)},
			want:    false,
		},
		{
			name:    "another plugin's PreToolUse hook",
			fixture: pluginFixture{name: plugin, hooks: preToolUse(wrapperCmd), script: foreignScript},
			scopes:  []map[string]any{enabledScope(plugin, true)},
			want:    false,
		},
		{
			name:    "script running some other tool's claude-code hook",
			fixture: pluginFixture{name: plugin, hooks: preToolUse(wrapperCmd), script: "#!/bin/sh\nexec \"$OTHER\" hook claude-code\n"},
			scopes:  []map[string]any{enabledScope(plugin, true)},
			want:    false,
		},
		{
			name:    "hook command with shell syntax is not resolved",
			fixture: pluginFixture{name: plugin, hooks: preToolUse("sh -c '${CLAUDE_PLUGIN_ROOT}/scripts/hook.sh | tee /tmp/x'"), script: wrapperScript},
			scopes:  []map[string]any{enabledScope(plugin, true)},
			want:    false,
		},
		{
			name:    "script outside the plugin root",
			fixture: pluginFixture{name: plugin, hooks: preToolUse("/usr/local/bin/hook.sh"), script: wrapperScript},
			scopes:  []map[string]any{enabledScope(plugin, true)},
			want:    false,
		},
		{
			// Only PreToolUse duplication matters — a banner hook is not what
			// makes Fence evaluate twice.
			name: "fence hook only on SessionStart",
			fixture: pluginFixture{name: plugin, script: wrapperScript,
				hooks: `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"${CLAUDE_PLUGIN_ROOT}/scripts/hook.sh session-start"}]}]}}`},
			scopes: []map[string]any{enabledScope(plugin, true)},
			want:   false,
		},
		{
			name:    "plugin ships no hooks file",
			fixture: pluginFixture{name: plugin, script: wrapperScript},
			scopes:  []map[string]any{enabledScope(plugin, true)},
			want:    false,
		},
		{
			name:    "unparseable hooks file",
			fixture: pluginFixture{name: plugin, hooks: "{not json", script: wrapperScript},
			scopes:  []map[string]any{enabledScope(plugin, true)},
			want:    false,
		},
		{
			name:    "wrapper command names a script the plugin never shipped",
			fixture: pluginFixture{name: plugin, hooks: preToolUse(wrapperCmd)},
			scopes:  []map[string]any{enabledScope(plugin, true)},
			want:    false,
		},
		{
			name:    "plugin missing from installed_plugins.json",
			fixture: pluginFixture{name: plugin, hooks: preToolUse(wrapperCmd), script: wrapperScript, noEntry: true},
			scopes:  []map[string]any{enabledScope(plugin, true)},
			want:    false,
		},
		{
			// Codex has no plugin layer, so its hooks can never come from one.
			name:    "agent without a plugin system",
			fixture: pluginFixture{name: plugin, hooks: preToolUse(wrapperCmd), script: wrapperScript},
			scopes:  []map[string]any{enabledScope(plugin, true)},
			agent:   hookAgents[1],
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			writePluginHome(t, tc.fixture)
			agent := tc.agent
			if agent.name == "" {
				agent = hookAgents[0]
			}
			provider, got := findPluginHookProvider(agent, tc.scopes...)
			if got != tc.want {
				t.Fatalf("findPluginHookProvider = %v (%s), want %v", got, provider.name, tc.want)
			}
			if got && provider.name != plugin {
				t.Errorf("provider name = %q, want %q", provider.name, plugin)
			}
		})
	}
}

// TestFindPluginHookProviderNoPluginsDir pins the fresh-machine case: no
// plugins installed at all must simply mean no provider, not an error path
// that could be mistaken for one.
func TestFindPluginHookProviderNoPluginsDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if _, found := findPluginHookProvider(hookAgents[0]); found {
		t.Fatal("reported a provider with no plugins installed")
	}
}

// TestHookAlreadyProvided pins the scope policy around standing down. The
// guard-gap scenario is the load-bearing case: plugin enablement is per-scope,
// so a global install must never stand down (the user scope enabling the
// plugin proves nothing about every project), and a project whose local
// settings disable the plugin must still get the hook.
func TestHookAlreadyProvided(t *testing.T) {
	const plugin = "hoop@hooplabs"
	enabled := `{"enabledPlugins":{"` + plugin + `":true}}`
	disabled := `{"enabledPlugins":{"` + plugin + `":false}}`

	tests := []struct {
		name   string
		user   string // ~/.claude/settings.json ("" = absent)
		target string // the settings file init writes ("" = absent)
		local  string // settings.local.json beside the target ("" = absent)
		global bool
		want   bool
	}{
		{
			name: "project init stands down when the user scope enables the plugin",
			user: enabled,
			want: true,
		},
		{
			// The guard gap: global init covers projects this function cannot
			// see, any of which may disable the plugin — never stand down.
			name:   "global init never stands down",
			user:   enabled,
			target: enabled,
			global: true,
			want:   false,
		},
		{
			name:   "project settings disabling the plugin means no provider",
			user:   enabled,
			target: disabled,
			want:   false,
		},
		{
			name:  "settings.local.json disabling the plugin means no provider",
			user:  enabled,
			local: disabled,
			want:  false,
		},
		{
			name:   "target re-enabling over a user-scope disable stands down",
			user:   disabled,
			target: enabled,
			want:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			writePluginHome(t, pluginFixture{
				name:   plugin,
				hooks:  preToolUse("${CLAUDE_PLUGIN_ROOT}/scripts/hook.sh"),
				script: wrapperScript,
			})
			home := os.Getenv("HOME")
			if tc.user != "" {
				writeTestFile(t, filepath.Join(home, ".claude", "settings.json"), tc.user)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, ".claude", "settings.json")
			if tc.global {
				path = filepath.Join(home, ".claude", "settings.json")
			}
			if tc.target != "" && !tc.global {
				writeTestFile(t, path, tc.target)
			}
			if tc.local != "" {
				writeTestFile(t, filepath.Join(filepath.Dir(path), "settings.local.json"), tc.local)
			}

			got, note := hookAlreadyProvided(hookAgents[0], path, tc.global)
			if got != tc.want {
				t.Fatalf("hookAlreadyProvided = %v, want %v", got, tc.want)
			}
			if got && note == "" {
				t.Error("standing down must explain itself in the note")
			}
		})
	}
}

func TestInstallStatusLineOnly(t *testing.T) {
	const foreignLine = "/usr/local/bin/my-statusline"

	tests := []struct {
		name      string
		initial   string
		want      hookInstallResult
		wantNote  bool
		preCmds   []string
		slCommand string
	}{
		{
			name:      "installs only the status line on a fresh file",
			want:      hookInstalled,
			slCommand: wantStatusCommand,
		},
		{
			// The dedup that motivates all of this: a hook left by an earlier
			// init, now redundant with the plugin's, is removed.
			name: "removes a duplicate hook an earlier init left",
			initial: `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + wantCommand + `"}]}]},
				"statusLine":{"type":"command","command":"` + wantStatusCommand + `"}}`,
			want:      hookUpdated,
			slCommand: wantStatusCommand,
		},
		{
			name:      "removes the banner hook too",
			initial:   `{"hooks":{"SessionStart":[{"matcher":"startup","hooks":[{"type":"command","command":"` + wantSessionCommand + `"}]}]}}`,
			want:      hookInstalled,
			slCommand: wantStatusCommand,
		},
		{
			name:      "idempotent once converged",
			initial:   `{"statusLine":{"type":"command","command":"` + wantStatusCommand + `"}}`,
			want:      hookUnchanged,
			slCommand: wantStatusCommand,
		},
		{
			// Nothing left to contribute: the plugin runs the hook and the
			// user owns the status line.
			name:      "leaves a foreign status line alone and adds nothing",
			initial:   `{"statusLine":{"type":"command","command":"` + foreignLine + `"}}`,
			want:      hookUnchanged,
			wantNote:  true,
			slCommand: foreignLine,
		},
		{
			name: "hooks of other tools survive",
			initial: `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[
				{"type":"command","command":"` + wantCommand + `"},
				{"type":"command","command":"/usr/local/bin/other hook claude"}]}]}}`,
			want:      hookInstalled,
			preCmds:   []string{"/usr/local/bin/other hook claude"},
			slCommand: wantStatusCommand,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// HOME isolation keeps the developer's own status line out of the
			// occupancy check.
			t.Setenv("HOME", t.TempDir())
			path := filepath.Join(t.TempDir(), ".claude", "settings.json")
			if tc.initial != "" {
				writeTestFile(t, path, tc.initial)
			}

			got, note, err := installStatusLineHooks(path, hookAgents[0], testSpecs(false), wantStatusCommand, false, true)
			if err != nil {
				t.Fatalf("installStatusLineHooks: %v", err)
			}
			if got != tc.want {
				t.Errorf("result = %v, want %v", got, tc.want)
			}
			if (note != "") != tc.wantNote {
				t.Errorf("note = %q, wantNote %v", note, tc.wantNote)
			}
			if tc.initial == "" && tc.want == hookUnchanged {
				return
			}
			if sl := statusLineCommandOf(t, path); sl != tc.slCommand {
				t.Errorf("statusLine = %q, want %q", sl, tc.slCommand)
			}
			gotPre := hookCommands(t, path, "PreToolUse")
			if len(gotPre) != len(tc.preCmds) {
				t.Fatalf("PreToolUse = %v, want %v", gotPre, tc.preCmds)
			}
			for i, want := range tc.preCmds {
				if gotPre[i] != want {
					t.Errorf("PreToolUse[%d] = %q, want %q", i, gotPre[i], want)
				}
			}
			if session := hookCommands(t, path, "SessionStart"); len(session) != 0 {
				t.Errorf("SessionStart = %v, want none", session)
			}
		})
	}
}

func TestRemoveHooksOnlyKeepsStatusLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	writeTestFile(t, path, `{"hooks":{
		"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"`+wantCommand+`"}]}],
		"SessionStart":[{"matcher":"startup","hooks":[{"type":"command","command":"`+wantSessionCommand+`"}]}]},
		"statusLine":{"type":"command","command":"`+wantStatusCommand+`"},
		"model":"opus"}`)

	got, err := removeHooks(path, claudeInvocation, true)
	if err != nil || got != hookRemoved {
		t.Fatalf("removeHooks = %v, %v; want hookRemoved, nil", got, err)
	}

	settings := readSettings(t, path)
	if _, present := settings["hooks"]; present {
		t.Errorf("hooks key survived: %v", settings["hooks"])
	}
	if cmd := statusLineCommandOf(t, path); cmd != wantStatusCommand {
		t.Errorf("statusLine = %q, want it kept as %q", cmd, wantStatusCommand)
	}
	if settings["model"] != "opus" {
		t.Errorf("unrelated settings lost: %v", settings)
	}
}

// TestRemoveHooksOnlyWithNothingButStatusLine pins that --hooks-only does not
// report a removal when only the status line is present: it is not a hook, and
// claiming otherwise would tell the user Fence was disarmed when it wasn't.
func TestRemoveHooksOnlyWithNothingButStatusLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	writeTestFile(t, path, `{"statusLine":{"type":"command","command":"`+wantStatusCommand+`"}}`)

	got, err := removeHooks(path, claudeInvocation, true)
	if err != nil || got != hookAbsent {
		t.Fatalf("removeHooks = %v, %v; want hookAbsent, nil", got, err)
	}
	if cmd := statusLineCommandOf(t, path); cmd != wantStatusCommand {
		t.Errorf("statusLine = %q, want it kept", cmd)
	}
}
