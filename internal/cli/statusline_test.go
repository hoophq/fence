package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const wantStatusCommand = wantCommand + " statusline"

// installStatus runs installStatusLineHooks the way `fence init` does, with
// the fixed test commands and HOME isolated so the developer's real
// ~/.claude/settings.json can't leak into the occupancy check.
func installStatus(t *testing.T, path string, quiet, global bool) (hookInstallResult, string, error) {
	t.Helper()
	return installStatusLineHooks(path, hookAgents[0], testSpecs(quiet), wantStatusCommand, global)
}

func statusLineCommandOf(t *testing.T, path string) string {
	t.Helper()
	cmd, _ := asMap(readSettings(t, path)["statusLine"])["command"].(string)
	return cmd
}

func TestInstallStatusLineHooks(t *testing.T) {
	legacyInstall := `{"hooks":{
		"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + wantCommand + `"}]}],
		"SessionStart":[{"matcher":"startup|resume|clear","hooks":[{"type":"command","command":"` + wantSessionCommand + `"}]}]}}`

	tests := []struct {
		name        string
		initial     string // "" means the settings file does not exist yet
		quiet       bool
		want        hookInstallResult
		wantNote    bool
		preCmds     []string // expected PreToolUse commands after the call
		sessionCmds []string // expected SessionStart commands (nil = none)
		slCommand   string   // expected statusLine.command ("" = key absent)
	}{
		{
			name:      "creates settings with the hook and the status line",
			want:      hookInstalled,
			preCmds:   []string{wantCommand},
			slCommand: wantStatusCommand,
		},
		{
			// The upgrade path from banner-era installs: the SessionStart hook
			// is replaced by the status line, PreToolUse stays.
			name:      "migrates a banner-era install to the status line",
			initial:   legacyInstall,
			want:      hookInstalled,
			preCmds:   []string{wantCommand},
			slCommand: wantStatusCommand,
		},
		{
			name: "idempotent when already converged",
			initial: `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + wantCommand + `"}]}]},
				"statusLine":{"type":"command","command":"` + wantStatusCommand + `"}}`,
			want:      hookUnchanged,
			preCmds:   []string{wantCommand},
			slCommand: wantStatusCommand,
		},
		{
			// The brew-cask trap again, now for the statusLine entry.
			name: "heals a stale binary path in the status line",
			initial: `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + wantCommand + `"}]}]},
				"statusLine":{"type":"command","command":"/opt/homebrew/Caskroom/fence/0.0.2/fence hook claude-code statusline"}}`,
			want:      hookUpdated,
			preCmds:   []string{wantCommand},
			slCommand: wantStatusCommand,
		},
		{
			name: "preserves an unmanaged flag while healing the status line",
			initial: `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + wantCommand + `"}]}]},
				"statusLine":{"type":"command","command":"/stale/fence hook claude-code statusline --rules /custom.yaml"}}`,
			want:      hookUpdated,
			preCmds:   []string{wantCommand},
			slCommand: wantStatusCommand + " --rules /custom.yaml",
		},
		{
			// The user's own status line owns the slot: Fence must not take it
			// (or shadow it) and announces through the banner instead.
			name:        "a foreign status line falls back to the banner",
			initial:     `{"statusLine":{"type":"command","command":"~/.claude/statusline.sh"}}`,
			want:        hookInstalled,
			wantNote:    true,
			preCmds:     []string{wantCommand},
			sessionCmds: []string{wantSessionCommand},
			slCommand:   "~/.claude/statusline.sh",
		},
		{
			// Even a statusLine shape we don't understand belongs to the user.
			name:        "an unrecognized statusLine shape counts as foreign",
			initial:     `{"statusLine":{"type":"static","text":"hello"}}`,
			want:        hookInstalled,
			wantNote:    true,
			preCmds:     []string{wantCommand},
			sessionCmds: []string{wantSessionCommand},
		},
		{
			name: "quiet toggles the PreToolUse hook, not the status line",
			initial: `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + wantCommand + `"}]}]},
				"statusLine":{"type":"command","command":"` + wantStatusCommand + `"}}`,
			quiet:     true,
			want:      hookUpdated,
			preCmds:   []string{wantCommand + " --quiet"},
			slCommand: wantStatusCommand,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			path := filepath.Join(t.TempDir(), ".claude", "settings.json")
			if tt.initial != "" {
				writeTestFile(t, path, tt.initial)
			}

			got, note, err := installStatus(t, path, tt.quiet, false)
			if err != nil {
				t.Fatalf("installStatusLineHooks: %v", err)
			}
			if got != tt.want {
				t.Fatalf("result = %v, want %v", got, tt.want)
			}
			if (note != "") != tt.wantNote {
				t.Fatalf("note = %q, wantNote %v", note, tt.wantNote)
			}

			for event, want := range map[string][]string{
				"PreToolUse":   tt.preCmds,
				"SessionStart": tt.sessionCmds,
			} {
				if cmds := hookCommands(t, path, event); !reflect.DeepEqual(cmds, want) {
					t.Errorf("%s commands = %q, want %q", event, cmds, want)
				}
			}
			if cmd := statusLineCommandOf(t, path); cmd != tt.slCommand {
				t.Errorf("statusLine.command = %q, want %q", cmd, tt.slCommand)
			}
		})
	}
}

// Keys the user added to Fence's own statusLine entry (padding, say) must
// survive a converge: init owns the command, nothing else.
func TestInstallStatusLineHooksKeepsUserKeys(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "settings.json")
	writeTestFile(t, path, `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"`+wantCommand+`"}]}]},
		"statusLine":{"type":"command","command":"/stale/fence hook claude-code statusline","padding":2}}`)

	if got, _, err := installStatus(t, path, false, false); err != nil || got != hookUpdated {
		t.Fatalf("installStatusLineHooks = %v, %v; want hookUpdated, nil", got, err)
	}

	sl := asMap(readSettings(t, path)["statusLine"])
	if cmd := sl["command"]; cmd != wantStatusCommand {
		t.Errorf("statusLine.command = %v, want %q", cmd, wantStatusCommand)
	}
	if pad := sl["padding"]; pad != float64(2) {
		t.Errorf("statusLine.padding = %v, want 2 kept", pad)
	}
}

// A project install must not shadow a status line configured in the
// user-level settings: shadowing clobbers the user's setup in effect.
func TestInstallStatusLineHooksRespectsUserScope(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"statusLine":{"type":"command","command":"ccusage statusline"}}`)
	path := filepath.Join(t.TempDir(), ".claude", "settings.json")

	got, note, err := installStatus(t, path, false, false)
	if err != nil || got != hookInstalled {
		t.Fatalf("installStatusLineHooks = %v, %v; want hookInstalled, nil", got, err)
	}
	if note == "" {
		t.Error("want a note explaining the fallback to the banner")
	}
	if cmd := statusLineCommandOf(t, path); cmd != "" {
		t.Errorf("project statusLine = %q, want none (it would shadow the user's)", cmd)
	}
	if cmds := hookCommands(t, path, "SessionStart"); !reflect.DeepEqual(cmds, []string{wantSessionCommand}) {
		t.Errorf("SessionStart commands = %q, want the banner fallback", cmds)
	}
}

// Fence's own status line in the user scope is not a conflict: a project
// install shadowing it changes nothing the user configured.
func TestInstallStatusLineHooksIgnoresOwnUserScopeEntry(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"statusLine":{"type":"command","command":"`+wantStatusCommand+`"}}`)
	path := filepath.Join(t.TempDir(), ".claude", "settings.json")

	got, note, err := installStatus(t, path, false, false)
	if err != nil || got != hookInstalled || note != "" {
		t.Fatalf("installStatusLineHooks = %v, %q, %v; want hookInstalled, no note, nil", got, note, err)
	}
	if cmd := statusLineCommandOf(t, path); cmd != wantStatusCommand {
		t.Errorf("statusLine.command = %q, want %q", cmd, wantStatusCommand)
	}
}

// settings.local.json overrides the project settings, so a status line there
// would shadow whatever Fence installs — respect it the same way.
func TestInstallStatusLineHooksRespectsLocalScope(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := filepath.Join(t.TempDir(), ".claude")
	writeTestFile(t, filepath.Join(dir, "settings.local.json"),
		`{"statusLine":{"type":"command","command":"my-statusline.sh"}}`)
	path := filepath.Join(dir, "settings.json")

	got, note, err := installStatus(t, path, false, false)
	if err != nil || got != hookInstalled {
		t.Fatalf("installStatusLineHooks = %v, %v; want hookInstalled, nil", got, err)
	}
	if note == "" {
		t.Error("want a note explaining the fallback to the banner")
	}
	if cmd := statusLineCommandOf(t, path); cmd != "" {
		t.Errorf("statusLine = %q, want none (settings.local.json owns the slot)", cmd)
	}
}

// A --global install converges the user file itself; other scopes are not
// consulted (a project's settings can't be known from here).
func TestInstallStatusLineHooksGlobal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".claude", "settings.json")

	got, note, err := installStatus(t, path, false, true)
	if err != nil || got != hookInstalled || note != "" {
		t.Fatalf("installStatusLineHooks = %v, %q, %v; want hookInstalled, no note, nil", got, note, err)
	}
	if cmd := statusLineCommandOf(t, path); cmd != wantStatusCommand {
		t.Errorf("statusLine.command = %q, want %q", cmd, wantStatusCommand)
	}
}

func TestInstallStatusLineHooksUnchangedDoesNotRewrite(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "settings.json")
	// Deliberately not in MarshalIndent formatting: a rewrite would reformat.
	initial := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + wantCommand + `"}]}]},` +
		`"statusLine":{"type":"command","command":"` + wantStatusCommand + `"}}`
	writeTestFile(t, path, initial)

	if got, _, err := installStatus(t, path, false, false); err != nil || got != hookUnchanged {
		t.Fatalf("installStatusLineHooks = %v, %v; want hookUnchanged, nil", got, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != initial {
		t.Errorf("file was rewritten despite no change:\n%s", data)
	}
}

func TestInstallStatusLineHooksRejectsInvalidJSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "settings.json")
	writeTestFile(t, path, "{not json")
	if _, _, err := installStatus(t, path, false, false); err == nil {
		t.Fatal("expected an error for invalid JSON, got nil")
	}
}

// init followed by uninstall must hand the file back as it was, statusLine
// included.
func TestRemoveHooksStatusLineRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "settings.json")
	writeTestFile(t, path, `{"model":"opus"}`)

	if _, _, err := installStatus(t, path, false, false); err != nil {
		t.Fatalf("installStatusLineHooks: %v", err)
	}
	if got, err := removeHooks(path, claudeInvocation); err != nil || got != hookRemoved {
		t.Fatalf("removeHooks = %v, %v; want hookRemoved, nil", got, err)
	}

	settings := readSettings(t, path)
	if _, ok := settings["hooks"]; ok {
		t.Errorf("hooks key left behind: %v", settings["hooks"])
	}
	if _, ok := settings["statusLine"]; ok {
		t.Errorf("statusLine key left behind: %v", settings["statusLine"])
	}
	if settings["model"] != "opus" {
		t.Errorf("model = %v, want opus", settings["model"])
	}
}

func TestRemoveHooksRemovesFenceStatusLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	writeTestFile(t, path, `{"model":"opus","statusLine":{"type":"command","command":"`+wantStatusCommand+`"}}`)

	if got, err := removeHooks(path, claudeInvocation); err != nil || got != hookRemoved {
		t.Fatalf("removeHooks = %v, %v; want hookRemoved, nil", got, err)
	}
	settings := readSettings(t, path)
	if _, ok := settings["statusLine"]; ok {
		t.Errorf("statusLine key left behind: %v", settings["statusLine"])
	}
	if settings["model"] != "opus" {
		t.Errorf("model = %v, want opus", settings["model"])
	}
}

// Uninstall must never take a status line that is not Fence's.
func TestRemoveHooksKeepsForeignStatusLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	initial := `{"statusLine":{"type":"command","command":"~/.claude/statusline.sh"}}`
	writeTestFile(t, path, initial)

	if got, err := removeHooks(path, claudeInvocation); err != nil || got != hookAbsent {
		t.Fatalf("removeHooks = %v, %v; want hookAbsent, nil", got, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != initial {
		t.Errorf("file was rewritten despite no change:\n%s", data)
	}
}

// The real command end to end: a fresh `fence init` writes the status line,
// not the banner hook, and says how to activate it.
func TestInitCommandInstallsStatusLine(t *testing.T) {
	isolateHome(t)
	out := runFence(t, "", "init")
	if !strings.Contains(out, "Installed the Fence hooks") {
		t.Fatalf("init output = %q, want an install confirmation", out)
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(wd, ".claude", "settings.json")
	if cmd := statusLineCommandOf(t, path); !strings.HasSuffix(cmd, " hook claude-code statusline") {
		t.Errorf("statusLine.command = %q, want a statusline invocation", cmd)
	}
	if cmds := hookCommands(t, path, "SessionStart"); cmds != nil {
		t.Errorf("SessionStart commands = %q, want none (the status line replaced the banner)", cmds)
	}
}
