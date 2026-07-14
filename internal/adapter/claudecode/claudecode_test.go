package claudecode

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hoophq/fence/internal/policy"
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

// decode parses a hook response for assertions. Absent keys stay absent — the
// tests below rely on that to prove no permission decision was emitted.
func decode(t *testing.T, raw string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, raw)
	}
	return out
}

func TestWriteDecision(t *testing.T) {
	rule := &policy.Rule{ID: "rm-recursive-home", Message: "Recursive delete of your home directory"}

	cases := []struct {
		name  string
		d     policy.Decision
		quiet bool

		wantEmpty    bool   // nothing at all on stdout
		wantDecision string // hookSpecificOutput.permissionDecision ("" = key must be absent)
		wantReason   string
		wantMsgParts []string // substrings the systemMessage must contain
	}{
		{
			name:         "deny blocks and announces",
			d:            policy.Decision{Effect: policy.EffectDeny, Rule: rule},
			wantDecision: "deny",
			wantReason:   "Recursive delete of your home directory",
			wantMsgParts: []string{"Fence blocked this", "Recursive delete", "(rule: rm-recursive-home)"},
		},
		{
			name:         "ask prompts and announces",
			d:            policy.Decision{Effect: policy.EffectAsk, Rule: rule},
			wantDecision: "ask",
			wantReason:   "Recursive delete of your home directory",
			wantMsgParts: []string{"Fence is asking first"},
		},
		{
			name:         "warn announces without a decision so the call proceeds",
			d:            policy.Decision{Effect: policy.EffectWarn, Rule: rule},
			wantMsgParts: []string{"Fence flagged this", "(rule: rm-recursive-home)"},
		},
		{
			name:         "allow announces without a decision by default",
			d:            policy.Decision{Effect: policy.EffectAllow},
			wantMsgParts: []string{"Fence allowed this"},
		},
		{
			name:      "quiet allow stays silent",
			d:         policy.Decision{Effect: policy.EffectAllow},
			quiet:     true,
			wantEmpty: true,
		},
		{
			name:         "deny from a pack default has no rule to cite",
			d:            policy.Decision{Effect: policy.EffectDeny},
			wantDecision: "deny",
			wantMsgParts: []string{"Fence blocked this"},
		},
		{
			name: "multi-line rule message collapses to one chat line",
			d: policy.Decision{Effect: policy.EffectDeny, Rule: &policy.Rule{
				ID:      "multi",
				Message: "line one\n  line two",
			}},
			wantDecision: "deny",
			wantReason:   "line one\n  line two",
			wantMsgParts: []string{"line one line two"},
		},
		{
			name: "a reason that already speaks as Fence is not double-branded",
			d: policy.Decision{Effect: policy.EffectDeny, Rule: &policy.Rule{
				ID:      "destructive-delete-sensitive",
				Message: "Fence blocked a recursive delete aimed at a sensitive location.",
			}},
			wantDecision: "deny",
			wantReason:   "Fence blocked a recursive delete aimed at a sensitive location.",
			wantMsgParts: []string{"🚧 Fence blocked a recursive delete"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteDecision(&buf, tc.d, tc.quiet); err != nil {
				t.Fatalf("WriteDecision: %v", err)
			}

			if tc.wantEmpty {
				if buf.Len() != 0 {
					t.Fatalf("want no output, got %s", buf.String())
				}
				return
			}

			out := decode(t, buf.String())

			msg, _ := out["systemMessage"].(string)
			for _, part := range tc.wantMsgParts {
				if !strings.Contains(msg, part) {
					t.Errorf("systemMessage = %q, want it to contain %q", msg, part)
				}
			}
			if strings.Contains(msg, "\n") {
				t.Errorf("systemMessage must be a single line, got %q", msg)
			}
			if n := strings.Count(msg, "Fence"); n != 1 {
				t.Errorf("systemMessage should name Fence exactly once, got %d in %q", n, msg)
			}

			hso, hasHSO := out["hookSpecificOutput"].(map[string]any)
			if tc.wantDecision == "" {
				// The load-bearing guard: no permission decision may leak. An
				// explicit "allow" would bypass the user's own permission
				// settings; an empty one is protocol garbage.
				if hasHSO {
					t.Fatalf("hookSpecificOutput must be absent, got %v", out["hookSpecificOutput"])
				}
				if strings.Contains(buf.String(), "permissionDecision") {
					t.Fatalf("output must not mention permissionDecision: %s", buf.String())
				}
				return
			}
			if !hasHSO {
				t.Fatalf("missing hookSpecificOutput in %s", buf.String())
			}
			if got := hso["permissionDecision"]; got != tc.wantDecision {
				t.Errorf("permissionDecision = %v, want %q", got, tc.wantDecision)
			}
			if got, _ := hso["permissionDecisionReason"].(string); got != tc.wantReason {
				t.Errorf("permissionDecisionReason = %q, want %q", got, tc.wantReason)
			}
			if got := hso["hookEventName"]; got != "PreToolUse" {
				t.Errorf("hookEventName = %v, want PreToolUse", got)
			}
		})
	}
}

func TestWriteSessionStart(t *testing.T) {
	cases := []struct {
		name    string
		version string
		packs   int
		rules   int
		failed  int
		want    []string
	}{
		{
			name:    "release version gets a v prefix",
			version: "0.0.4", packs: 3, rules: 42,
			want: []string{"Fence v0.0.4", "3 packs", "42 rules", "guarding this session"},
		},
		{
			name:    "git-describe version is kept as-is",
			version: "v0.0.4-2-gabc1234", packs: 2, rules: 40,
			want: []string{"Fence v0.0.4-2-gabc1234"},
		},
		{
			name:    "dev build and singular counts",
			version: "dev", packs: 1, rules: 1,
			want: []string{"Fence dev", "1 pack,", "1 rule)"},
		},
		{
			name:  "no version at all",
			packs: 1, rules: 34,
			want: []string{"🚧 Fence is guarding this session"},
		},
		{
			name:    "a failed ambient pack is called out",
			version: "0.0.4", packs: 1, rules: 19, failed: 1,
			want: []string{"⚠️ 1 rulepack failed to load"},
		},
		{
			name:    "several failed packs pluralize",
			version: "0.0.4", packs: 1, rules: 19, failed: 2,
			want: []string{"2 rulepacks failed to load"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteSessionStart(&buf, tc.version, tc.packs, tc.rules, tc.failed); err != nil {
				t.Fatalf("WriteSessionStart: %v", err)
			}
			out := decode(t, buf.String())
			msg, _ := out["systemMessage"].(string)
			for _, part := range tc.want {
				if !strings.Contains(msg, part) {
					t.Errorf("systemMessage = %q, want it to contain %q", msg, part)
				}
			}
			// A clean load must not hedge the banner.
			if tc.failed == 0 && strings.Contains(msg, "failed to load") {
				t.Errorf("clean banner mentions failures: %q", msg)
			}
			// A banner must never carry a permission decision.
			if _, ok := out["hookSpecificOutput"]; ok {
				t.Fatalf("banner must not include hookSpecificOutput: %s", buf.String())
			}
		})
	}
}

func TestWriteSessionStartDegraded(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSessionStartDegraded(&buf); err != nil {
		t.Fatalf("WriteSessionStartDegraded: %v", err)
	}
	out := decode(t, buf.String())
	msg, _ := out["systemMessage"].(string)
	if !strings.Contains(msg, "NOT being screened") {
		t.Errorf("degraded banner must say the session is unscreened, got %q", msg)
	}
	if _, ok := out["hookSpecificOutput"]; ok {
		t.Fatalf("degraded banner must not include hookSpecificOutput: %s", buf.String())
	}
}

func TestWriteStatusLine(t *testing.T) {
	cases := []struct {
		name    string
		version string
		packs   int
		rules   int
		failed  int
		want    []string
	}{
		{
			name:    "release version gets a v prefix",
			version: "0.0.4", packs: 3, rules: 42,
			want: []string{"🚧 Fence v0.0.4", "3 packs", "42 rules"},
		},
		{
			name:    "git-describe version is kept as-is",
			version: "v0.0.4-2-gabc1234", packs: 2, rules: 40,
			want: []string{"Fence v0.0.4-2-gabc1234"},
		},
		{
			name:    "dev build and singular counts",
			version: "dev", packs: 1, rules: 1,
			want: []string{"Fence dev", "1 pack ·", "1 rule"},
		},
		{
			name:  "no version at all",
			packs: 1, rules: 34,
			want: []string{"🚧 Fence · 1 pack · 34 rules"},
		},
		{
			name:    "a failed ambient pack is called out",
			version: "0.0.4", packs: 1, rules: 19, failed: 1,
			want: []string{"⚠️ 1 rulepack failed to load"},
		},
		{
			name:    "several failed packs pluralize",
			version: "0.0.4", packs: 1, rules: 19, failed: 2,
			want: []string{"2 rulepacks failed to load"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteStatusLine(&buf, tc.version, tc.packs, tc.rules, tc.failed); err != nil {
				t.Fatalf("WriteStatusLine: %v", err)
			}
			out := buf.String()
			for _, part := range tc.want {
				if !strings.Contains(out, part) {
					t.Errorf("status line = %q, want it to contain %q", out, part)
				}
			}
			// The statusLine protocol is rendered stdout: one plain-text line,
			// not the hook JSON envelope.
			if strings.Contains(out, "{") || strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
				t.Errorf("status line must be one plain-text line, got %q", out)
			}
			// A clean load must not hedge the line.
			if tc.failed == 0 && strings.Contains(out, "failed to load") {
				t.Errorf("clean status line mentions failures: %q", out)
			}
		})
	}
}

func TestWriteStatusLineDegraded(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteStatusLineDegraded(&buf); err != nil {
		t.Fatalf("WriteStatusLineDegraded: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "NOT screened") {
		t.Errorf("degraded status line must say the session is unscreened, got %q", out)
	}
	if strings.Contains(out, "{") {
		t.Errorf("degraded status line must be plain text, got %q", out)
	}
}
