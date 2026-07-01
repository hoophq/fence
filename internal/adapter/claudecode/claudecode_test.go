package claudecode

import (
	"strings"
	"testing"

	"github.com/hoophq/leash/internal/policy"
)

func TestParseActionContent(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		wantKind    policy.ActionKind
		wantPath    string
		wantContent string
		wantCommand string
	}{
		{
			name:        "write carries full content",
			input:       `{"cwd":".","tool_name":"Write","tool_input":{"file_path":"/p/package.json","content":"{\"scripts\":{\"postinstall\":\"x\"}}"}}`,
			wantKind:    policy.ActionFileWrite,
			wantPath:    "/p/package.json",
			wantContent: `{"scripts":{"postinstall":"x"}}`,
		},
		{
			name:        "edit carries new_string fragment",
			input:       `{"cwd":".","tool_name":"Edit","tool_input":{"file_path":"/p/package.json","old_string":"a","new_string":"\"postinstall\": \"x\""}}`,
			wantKind:    policy.ActionFileWrite,
			wantPath:    "/p/package.json",
			wantContent: `"postinstall": "x"`,
		},
		{
			name:        "multiedit joins new_strings",
			input:       `{"cwd":".","tool_name":"MultiEdit","tool_input":{"file_path":"/p/f","edits":[{"old_string":"a","new_string":"one"},{"old_string":"b","new_string":"two"}]}}`,
			wantKind:    policy.ActionFileWrite,
			wantPath:    "/p/f",
			wantContent: "one\ntwo\n",
		},
		{
			name:        "bash has command and no content",
			input:       `{"cwd":".","tool_name":"Bash","tool_input":{"command":"ls -la"}}`,
			wantKind:    policy.ActionShell,
			wantCommand: "ls -la",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := ParseAction(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("ParseAction: %v", err)
			}
			if a.Kind != tc.wantKind {
				t.Errorf("Kind = %q, want %q", a.Kind, tc.wantKind)
			}
			if a.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", a.Path, tc.wantPath)
			}
			if a.Content != tc.wantContent {
				t.Errorf("Content = %q, want %q", a.Content, tc.wantContent)
			}
			if a.Command != tc.wantCommand {
				t.Errorf("Command = %q, want %q", a.Command, tc.wantCommand)
			}
		})
	}
}
