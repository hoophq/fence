package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolateHome points HOME at an empty temp dir and moves into another, so the
// developer's real ~/.leash and any project .leash.yaml never leak into the
// engine under test. Returns the fake home.
func isolateHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	chdirEmpty(t)
	return home
}

// runLeash executes the real root command — flag parsing, subcommand dispatch,
// stdin/stdout plumbing — and returns stdout.
func runLeash(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	root := NewRootCommand("1.2.3")
	root.SetIn(strings.NewReader(stdin))
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(io.Discard)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		t.Fatalf("leash %s: %v", strings.Join(args, " "), err)
	}
	return out.String()
}

func TestHookClaudeCodeDeny(t *testing.T) {
	isolateHome(t)
	out := runLeash(t, `{"cwd":".","tool_name":"Bash","tool_input":{"command":"rm -rf ~"}}`,
		"hook", "claude-code")
	for _, want := range []string{`"permissionDecision":"deny"`, `"systemMessage"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %s:\n%s", want, out)
		}
	}
}

func TestHookClaudeCodeAllowIsSilent(t *testing.T) {
	isolateHome(t)
	out := runLeash(t, `{"cwd":".","tool_name":"Bash","tool_input":{"command":"ls -la"}}`,
		"hook", "claude-code")
	if out != "" {
		t.Fatalf("an allowed call must produce no output, got:\n%s", out)
	}
}

func TestHookClaudeCodeVerboseAllow(t *testing.T) {
	isolateHome(t)
	out := runLeash(t, `{"cwd":".","tool_name":"Bash","tool_input":{"command":"ls -la"}}`,
		"hook", "claude-code", "--verbose")
	if !strings.Contains(out, "Leash allowed this") {
		t.Errorf("verbose allow missing the notice:\n%s", out)
	}
	// The bypass guard, end to end: verbose feedback must never carry a
	// permission decision.
	if strings.Contains(out, "permissionDecision") {
		t.Fatalf("verbose allow must not emit a permission decision:\n%s", out)
	}
}

func TestHookClaudeCodeFailsOpenOnGarbage(t *testing.T) {
	isolateHome(t)
	out := runLeash(t, "definitely not json", "hook", "claude-code")
	if out != "" {
		t.Fatalf("unparseable input must produce no output (fail open), got:\n%s", out)
	}
}

func TestHookSessionStartBanner(t *testing.T) {
	isolateHome(t)
	out := runLeash(t, "", "hook", "claude-code", "session-start")
	for _, want := range []string{"Leash v1.2.3 is guarding this session", "(1 pack,"} {
		if !strings.Contains(out, want) {
			t.Errorf("banner missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "failed to load") {
		t.Errorf("clean banner mentions failures:\n%s", out)
	}
	if strings.Contains(out, "hookSpecificOutput") {
		t.Fatalf("banner must not carry a permission decision:\n%s", out)
	}
}

func TestHookSessionStartReportsFailedPack(t *testing.T) {
	home := isolateHome(t)
	packs := filepath.Join(home, ".leash", "packs")
	if err := os.MkdirAll(packs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packs, "broken.yaml"),
		[]byte("rules:\n  - id: x\n    effect: nope\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := runLeash(t, "", "hook", "claude-code", "session-start")
	if !strings.Contains(out, "1 rulepack failed to load") {
		t.Errorf("banner does not report the broken pack:\n%s", out)
	}
	// The recommended pack still protects underneath.
	if !strings.Contains(out, "(1 pack,") {
		t.Errorf("banner should still count the recommended pack:\n%s", out)
	}
}
