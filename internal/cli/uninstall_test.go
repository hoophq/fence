package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRemoveHooks(t *testing.T) {
	fenceOnly := `{"hooks":{
		"PreToolUse":[{"matcher":"Bash|Write","hooks":[{"type":"command","command":"` + wantCommand + `"}]}],
		"SessionStart":[{"matcher":"startup|resume|clear","hooks":[{"type":"command","command":"` + wantSessionCommand + `"}]}]}}`

	tests := []struct {
		name    string
		initial string // "" = missing file
		want    hookRemoveResult
		// wantCmds is what hookCommands must return per event afterwards.
		preCmds     []string
		sessionCmds []string
	}{
		{
			name:    "removes both hooks",
			initial: fenceOnly,
			want:    hookRemoved,
		},
		{
			name:    "missing file is a no-op",
			initial: "",
			want:    hookAbsent,
		},
		{
			name: "quiet and stale-path variants are still ours",
			initial: `{"hooks":{
				"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/stale/fence hook claude-code --quiet"}]}],
				"SessionStart":[{"matcher":"startup","hooks":[{"type":"command","command":"fence hook claude-code session-start"}]}]}}`,
			want: hookRemoved,
		},
		{
			name: "a hand-added flag does not hide the hook",
			initial: `{"hooks":{
				"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + wantCommand + ` --rules /custom.yaml"}]}]}}`,
			want: hookRemoved,
		},
		{
			name: "an unrelated hook in the same event survives",
			initial: `{"hooks":{
				"PreToolUse":[
					{"matcher":"Bash","hooks":[{"type":"command","command":"echo hi"}]},
					{"matcher":"Bash|Write","hooks":[{"type":"command","command":"` + wantCommand + `"}]}]}}`,
			want:    hookRemoved,
			preCmds: []string{"echo hi"},
		},
		{
			name: "an unrelated command sharing our entry survives",
			initial: `{"hooks":{
				"PreToolUse":[{"matcher":"Bash","hooks":[
					{"type":"command","command":"` + wantCommand + `"},
					{"type":"command","command":"echo hi"}]}]}}`,
			want:    hookRemoved,
			preCmds: []string{"echo hi"},
		},
		{
			name: "a string that merely mentions the invocation is not ours",
			initial: `{"hooks":{
				"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo fence hook claude-code | wc -l"}]}]}}`,
			want:    hookAbsent,
			preCmds: []string{"echo fence hook claude-code | wc -l"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".claude", "settings.json")
			if tt.initial != "" {
				writeTestFile(t, path, tt.initial)
			}

			got, err := removeHooks(path, claudeInvocation)
			if err != nil {
				t.Fatalf("removeHooks: %v", err)
			}
			if got != tt.want {
				t.Fatalf("result = %v, want %v", got, tt.want)
			}

			if tt.initial == "" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("uninstall must not create the settings file")
				}
				return
			}
			for event, want := range map[string][]string{
				"PreToolUse":   tt.preCmds,
				"SessionStart": tt.sessionCmds,
			} {
				cmds := hookCommands(t, path, event)
				if !reflect.DeepEqual(cmds, want) {
					t.Fatalf("%s commands = %q, want %q", event, cmds, want)
				}
			}
		})
	}
}

// init followed by uninstall must hand the file back as it was: unrelated
// settings intact, no empty hooks containers left behind.
func TestRemoveHooksRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	writeTestFile(t, path, `{"permissions":{"allow":["Bash(ls *)"]},"model":"opus"}`)

	if _, err := installHooks(path, testSpecs(false)); err != nil {
		t.Fatalf("installHooks: %v", err)
	}
	if got, err := removeHooks(path, claudeInvocation); err != nil || got != hookRemoved {
		t.Fatalf("removeHooks = %v, %v; want hookRemoved, nil", got, err)
	}

	settings := readSettings(t, path)
	if _, ok := settings["hooks"]; ok {
		t.Errorf("hooks key left behind: %v", settings["hooks"])
	}
	if settings["model"] != "opus" {
		t.Errorf("model = %v, want opus", settings["model"])
	}
	allow := asSlice(asMap(settings["permissions"])["allow"])
	if len(allow) != 1 || allow[0] != "Bash(ls *)" {
		t.Errorf("permissions.allow = %v, want [Bash(ls *)]", allow)
	}
}

// A no-op uninstall must not rewrite (and reformat) the file.
func TestRemoveHooksNoOpDoesNotRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	// Deliberately not in MarshalIndent formatting: a rewrite would reformat.
	initial := `{"model":"opus","hooks":{"PostToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo hi"}]}]}}`
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

func TestRemoveHooksRejectsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	writeTestFile(t, path, "{not json")
	if _, err := removeHooks(path, claudeInvocation); err == nil {
		t.Fatal("expected an error for invalid JSON, got nil")
	}
}

// The real command end to end, against settings as `fence init` writes them.
// (init itself can't produce them here: under `go test` the binary is
// cli.test, not fence, so containsHook wouldn't own the result.)
func TestUninstallCommand(t *testing.T) {
	isolateHome(t)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(wd, ".claude", "settings.json")
	writeTestFile(t, path, `{"model":"opus","hooks":{
		"PreToolUse":[{"matcher":"Bash|Write","hooks":[{"type":"command","command":"`+wantCommand+`"}]}],
		"SessionStart":[{"matcher":"startup|resume|clear","hooks":[{"type":"command","command":"`+wantSessionCommand+`"}]}]}}`)

	out := runFence(t, "", "uninstall")
	if !strings.Contains(out, "Removed the Fence hooks") {
		t.Fatalf("uninstall output = %q, want a removal confirmation", out)
	}

	settings := readSettings(t, path)
	if _, ok := settings["hooks"]; ok {
		t.Fatalf("hooks left in settings after uninstall: %v", settings["hooks"])
	}
	if settings["model"] != "opus" {
		t.Fatalf("model = %v, want opus preserved", settings["model"])
	}

	// Running it again is a friendly no-op.
	if out := runFence(t, "", "uninstall"); !strings.Contains(out, "No Fence hooks found") {
		t.Fatalf("second uninstall output = %q, want the no-op message", out)
	}
}
