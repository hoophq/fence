package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	wantCommand        = "/opt/homebrew/bin/leash hook claude-code"
	wantSessionCommand = wantCommand + " session-start"
)

// testSpecs mirrors desiredHooks with a fixed binary path.
func testSpecs(quiet bool) []hookSpec {
	pre := wantCommand
	if quiet {
		pre += " --quiet"
	}
	return []hookSpec{
		{event: "PreToolUse", matcher: toolMatcher, command: pre},
		{event: "SessionStart", matcher: sessionStartMatcher, command: wantSessionCommand},
	}
}

func readSettings(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("settings not valid JSON: %v", err)
	}
	return settings
}

// hookCommands walks hooks.<event> and returns every hook command string.
func hookCommands(t *testing.T, path, event string) []string {
	t.Helper()
	var cmds []string
	for _, e := range asSlice(asMap(readSettings(t, path)["hooks"])[event]) {
		for _, h := range asSlice(asMap(e)["hooks"]) {
			if cmd, ok := asMap(h)["command"].(string); ok {
				cmds = append(cmds, cmd)
			}
		}
	}
	return cmds
}

func TestInstallHooks(t *testing.T) {
	tests := []struct {
		name        string
		initial     string // "" means the settings file does not exist yet
		quiet       bool
		want        hookInstallResult
		preCmds     []string // expected PreToolUse commands after the call, in order
		sessionCmds []string // expected SessionStart commands after the call, in order
	}{
		{
			name:        "creates settings file with both hooks",
			want:        hookInstalled,
			preCmds:     []string{wantCommand},
			sessionCmds: []string{wantSessionCommand},
		},
		{
			name: "appends alongside unrelated hooks",
			initial: `{"permissions":{"allow":["Bash(ls *)"]},
				"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo hi"}]}]}}`,
			want:        hookInstalled,
			preCmds:     []string{"echo hi", wantCommand},
			sessionCmds: []string{wantSessionCommand},
		},
		{
			// The upgrade path from installs made before the SessionStart
			// banner existed: PreToolUse is current, the banner hook is not
			// there yet.
			name: "adds the session banner to a pre-banner install",
			initial: `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[
				{"type":"command","command":"/opt/homebrew/bin/leash hook claude-code"}]}]}}`,
			want:        hookInstalled,
			preCmds:     []string{wantCommand},
			sessionCmds: []string{wantSessionCommand},
		},
		{
			name: "idempotent when both hooks already match",
			initial: `{"hooks":{
				"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/homebrew/bin/leash hook claude-code"}]}],
				"SessionStart":[{"matcher":"startup|resume|clear","hooks":[{"type":"command","command":"/opt/homebrew/bin/leash hook claude-code session-start"}]}]}}`,
			want:        hookUnchanged,
			preCmds:     []string{wantCommand},
			sessionCmds: []string{wantSessionCommand},
		},
		{
			// The brew-cask trap: a previous init resolved the symlink into a
			// version-pinned Caskroom path that no longer exists after upgrade.
			// Re-running init must heal both hooks, not report "already present".
			name: "heals stale binary paths in both hooks",
			initial: `{"hooks":{
				"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/homebrew/Caskroom/leash/0.0.2/leash hook claude-code"}]}],
				"SessionStart":[{"matcher":"startup|resume|clear","hooks":[{"type":"command","command":"/opt/homebrew/Caskroom/leash/0.0.2/leash hook claude-code session-start"}]}]}}`,
			want:        hookUpdated,
			preCmds:     []string{wantCommand},
			sessionCmds: []string{wantSessionCommand},
		},
		{
			name:        "bare PATH command is recognized and healed to absolute",
			initial:     `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"leash hook claude-code"}]}]}}`,
			want:        hookInstalled, // healed + banner added
			preCmds:     []string{wantCommand},
			sessionCmds: []string{wantSessionCommand},
		},
		{
			name: "quiet toggles on",
			initial: `{"hooks":{
				"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/homebrew/bin/leash hook claude-code"}]}],
				"SessionStart":[{"matcher":"startup|resume|clear","hooks":[{"type":"command","command":"/opt/homebrew/bin/leash hook claude-code session-start"}]}]}}`,
			quiet:       true,
			want:        hookUpdated,
			preCmds:     []string{wantCommand + " --quiet"},
			sessionCmds: []string{wantSessionCommand},
		},
		{
			name: "quiet toggles back off",
			initial: `{"hooks":{
				"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/homebrew/bin/leash hook claude-code --quiet"}]}],
				"SessionStart":[{"matcher":"startup|resume|clear","hooks":[{"type":"command","command":"/opt/homebrew/bin/leash hook claude-code session-start"}]}]}}`,
			want:        hookUpdated,
			preCmds:     []string{wantCommand},
			sessionCmds: []string{wantSessionCommand},
		},
		{
			// The upgrade path from installs made when allowed-call notices were
			// opt-in: the legacy --verbose token asked for what is now the
			// default, so converging drops it.
			name: "legacy --verbose converges to the plain command",
			initial: `{"hooks":{
				"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/homebrew/bin/leash hook claude-code --verbose"}]}],
				"SessionStart":[{"matcher":"startup|resume|clear","hooks":[{"type":"command","command":"/opt/homebrew/bin/leash hook claude-code session-start"}]}]}}`,
			want:        hookUpdated,
			preCmds:     []string{wantCommand},
			sessionCmds: []string{wantSessionCommand},
		},
		{
			// A flag init doesn't manage (e.g. a hand-added --rules) must ride
			// along when the stale binary path is healed — dropping it would
			// silently weaken the user's setup.
			name: "preserves an unmanaged flag while healing a stale path",
			initial: `{"hooks":{
				"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/homebrew/Caskroom/leash/0.0.2/leash hook claude-code --rules /custom.yaml"}]}],
				"SessionStart":[{"matcher":"startup|resume|clear","hooks":[{"type":"command","command":"/opt/homebrew/bin/leash hook claude-code session-start"}]}]}}`,
			want:        hookUpdated,
			preCmds:     []string{wantCommand + " --rules /custom.yaml"},
			sessionCmds: []string{wantSessionCommand},
		},
		{
			name: "preserves an unmanaged flag across a quiet toggle",
			initial: `{"hooks":{
				"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/homebrew/bin/leash hook claude-code --rules /custom.yaml"}]}],
				"SessionStart":[{"matcher":"startup|resume|clear","hooks":[{"type":"command","command":"/opt/homebrew/bin/leash hook claude-code session-start"}]}]}}`,
			quiet:       true,
			want:        hookUpdated,
			preCmds:     []string{wantCommand + " --quiet --rules /custom.yaml"},
			sessionCmds: []string{wantSessionCommand},
		},
		{
			name: "an unmanaged flag alone is not a change",
			initial: `{"hooks":{
				"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/homebrew/bin/leash hook claude-code --rules /custom.yaml"}]}],
				"SessionStart":[{"matcher":"startup|resume|clear","hooks":[{"type":"command","command":"/opt/homebrew/bin/leash hook claude-code session-start"}]}]}}`,
			want:        hookUnchanged,
			preCmds:     []string{wantCommand + " --rules /custom.yaml"},
			sessionCmds: []string{wantSessionCommand},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".claude", "settings.json")
			if tt.initial != "" {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(tt.initial), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			got, err := installHooks(path, testSpecs(tt.quiet))
			if err != nil {
				t.Fatalf("installHooks: %v", err)
			}
			if got != tt.want {
				t.Fatalf("result = %v, want %v", got, tt.want)
			}

			for event, want := range map[string][]string{
				"PreToolUse":   tt.preCmds,
				"SessionStart": tt.sessionCmds,
			} {
				cmds := hookCommands(t, path, event)
				if len(cmds) != len(want) {
					t.Fatalf("%s commands = %q, want %q", event, cmds, want)
				}
				for i := range cmds {
					if cmds[i] != want[i] {
						t.Fatalf("%s command[%d] = %q, want %q", event, i, cmds[i], want[i])
					}
				}
			}
		})
	}
}

// The pre-default spelling `leash init --verbose` must keep parsing (users
// type it from muscle memory): it asked for what is now the default, so the
// written hook command carries no token at all.
func TestInitLegacyVerboseFlagStillAccepted(t *testing.T) {
	isolateHome(t)
	runLeash(t, "", "init", "--verbose")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cmds := hookCommands(t, filepath.Join(wd, ".claude", "settings.json"), "PreToolUse")
	if len(cmds) != 1 || !strings.HasSuffix(cmds[0], " hook claude-code") {
		t.Fatalf("PreToolUse commands = %q, want one plain hook command", cmds)
	}
}

// A matcher the user narrowed (e.g. dropped WebFetch) must survive healing:
// init converges commands, never matchers.
func TestInstallHooksPreservesCustomMatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	initial := `{"hooks":{
		"PreToolUse":[{"matcher":"Bash|Write","hooks":[{"type":"command","command":"/stale/leash hook claude-code"}]}],
		"SessionStart":[{"matcher":"startup","hooks":[{"type":"command","command":"/stale/leash hook claude-code session-start"}]}]}}`
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	if got, err := installHooks(path, testSpecs(false)); err != nil || got != hookUpdated {
		t.Fatalf("installHooks = %v, %v; want hookUpdated, nil", got, err)
	}

	hooks := asMap(readSettings(t, path)["hooks"])
	if m := asMap(asSlice(hooks["PreToolUse"])[0])["matcher"]; m != "Bash|Write" {
		t.Errorf("PreToolUse matcher = %v, want the user's Bash|Write kept", m)
	}
	if m := asMap(asSlice(hooks["SessionStart"])[0])["matcher"]; m != "startup" {
		t.Errorf("SessionStart matcher = %v, want the user's startup kept", m)
	}
}

func TestInstallHooksPreservesUnrelatedSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	initial := `{"permissions":{"allow":["Bash(ls *)"]},"model":"opus"}`
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := installHooks(path, testSpecs(false)); err != nil {
		t.Fatalf("installHooks: %v", err)
	}

	settings := readSettings(t, path)
	if settings["model"] != "opus" {
		t.Errorf("model = %v, want opus", settings["model"])
	}
	allow := asSlice(asMap(settings["permissions"])["allow"])
	if len(allow) != 1 || allow[0] != "Bash(ls *)" {
		t.Errorf("permissions.allow = %v, want [Bash(ls *)]", allow)
	}
}

func TestInstallHooksUnchangedDoesNotRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	// Deliberately not in MarshalIndent formatting: a rewrite would reformat.
	initial := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + wantCommand + `"}]}],` +
		`"SessionStart":[{"matcher":"startup|resume|clear","hooks":[{"type":"command","command":"` + wantSessionCommand + `"}]}]}}`
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	if got, err := installHooks(path, testSpecs(false)); err != nil || got != hookUnchanged {
		t.Fatalf("installHooks = %v, %v; want hookUnchanged, nil", got, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != initial {
		t.Errorf("file was rewritten despite no change:\n%s", data)
	}
}

func TestInstallHooksRejectsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := installHooks(path, testSpecs(false)); err == nil {
		t.Fatal("expected an error for invalid JSON, got nil")
	}
}

func TestDesiredHooks(t *testing.T) {
	specs := desiredHooks(false)
	if len(specs) != 2 {
		t.Fatalf("desiredHooks returned %d specs, want 2", len(specs))
	}
	if specs[0].event != "PreToolUse" || !strings.HasSuffix(specs[0].command, " hook claude-code") {
		t.Errorf("PreToolUse spec = %+v", specs[0])
	}
	if specs[1].event != "SessionStart" || !strings.HasSuffix(specs[1].command, " hook claude-code session-start") {
		t.Errorf("SessionStart spec = %+v", specs[1])
	}

	quiet := desiredHooks(true)
	if !strings.HasSuffix(quiet[0].command, " hook claude-code --quiet") {
		t.Errorf("quiet PreToolUse command = %q, want --quiet suffix", quiet[0].command)
	}
	if quiet[1].command != specs[1].command {
		t.Errorf("quiet must not change the SessionStart command, got %q", quiet[1].command)
	}
}

func TestHookInvocationKeepsSymlinksUnresolved(t *testing.T) {
	got := hookInvocation()
	if !strings.HasSuffix(got, " hook claude-code") {
		t.Fatalf("hookInvocation() = %q, want suffix %q", got, " hook claude-code")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable: %v", err)
	}
	// The invocation must use the executable path as-is — resolving symlinks is
	// what pinned brew users to a Caskroom path that dies on upgrade.
	if want := exe + " hook claude-code"; got != want {
		t.Errorf("hookInvocation() = %q, want %q", got, want)
	}
}

func TestContainsHook(t *testing.T) {
	tests := []struct {
		cmd  string
		want bool
	}{
		{"leash hook claude-code", true},
		{"/opt/homebrew/bin/leash hook claude-code", true},
		{"/Users/dev/go/bin/leash hook claude-code", true},
		{"leash hook claude-code session-start", true},
		{"/opt/homebrew/bin/leash hook claude-code session-start", true},
		{"/opt/homebrew/bin/leash hook claude-code --quiet", true},
		{"/opt/homebrew/bin/leash hook claude-code --verbose", true}, // legacy installs
		{"leash hook claude-codex", false},
		{"leash check 'rm -rf ~'", false},
		{"echo leash hook claude-code | wc -l", false},
		{"leash hook claude-code && rm -rf /", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := containsHook(tt.cmd); got != tt.want {
			t.Errorf("containsHook(%q) = %v, want %v", tt.cmd, got, tt.want)
		}
	}
}

// Windows is documented out at 1.0: init must refuse honestly rather than
// install a hook that was never verified there. See issue #26.
func TestInitSupportedOS(t *testing.T) {
	if err := initSupportedOS("windows"); err == nil {
		t.Fatal("init on windows must refuse with an error")
	} else if !strings.Contains(err.Error(), "WSL") {
		t.Errorf("the refusal should point at WSL, got %q", err)
	}
	for _, goos := range []string{"darwin", "linux"} {
		if err := initSupportedOS(goos); err != nil {
			t.Errorf("initSupportedOS(%q) = %v, want nil", goos, err)
		}
	}
}
