package codex

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hoophq/fence/internal/policy"
)

func TestParseActionsBash(t *testing.T) {
	in := `{"cwd":"/w","tool_name":"Bash","tool_input":{"command":"rm -rf ~"}}`
	actions, err := ParseActions(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 {
		t.Fatalf("got %d actions, want 1", len(actions))
	}
	a := actions[0]
	if a.Kind != policy.ActionShell || a.Command != "rm -rf ~" || a.Cwd != "/w" {
		t.Fatalf("action = %+v", a)
	}
}

// apply_patch expands to one file_write per touched file, with the added
// lines as content — so path_glob and manifest_hook rules see each file.
func TestParseActionsApplyPatch(t *testing.T) {
	patch := "*** Begin Patch\n" +
		"*** Add File: package.json\n" +
		"+{\n" +
		"+  \"scripts\": {\"postinstall\": \"evil.sh\"}\n" +
		"+}\n" +
		"*** Update File: src/app.js\n" +
		"@@ context\n" +
		"-old line\n" +
		"+new line\n" +
		"*** Move to: src/renamed.js\n" +
		"*** Delete File: docs/old.md\n" +
		"*** End Patch"
	payload, _ := json.Marshal(map[string]any{
		"cwd":        "/w",
		"tool_name":  "apply_patch",
		"tool_input": map[string]string{"command": patch},
	})

	actions, err := ParseActions(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}

	want := []struct {
		path    string
		content string
	}{
		{"package.json", "{\n  \"scripts\": {\"postinstall\": \"evil.sh\"}\n}\n"},
		{"src/app.js", "new line\n"},
		{"src/renamed.js", ""},
		{"docs/old.md", ""},
	}
	if len(actions) != len(want) {
		t.Fatalf("got %d actions, want %d: %+v", len(actions), len(want), actions)
	}
	for i, w := range want {
		a := actions[i]
		if a.Kind != policy.ActionFileWrite || a.Path != w.path || a.Content != w.content || a.Cwd != "/w" {
			t.Errorf("action[%d] = %+v, want path %q content %q", i, a, w.path, w.content)
		}
	}
}

func TestParseActionsUnknownTool(t *testing.T) {
	cases := []string{
		`{"cwd":"/w","tool_name":"mcp__filesystem__read","tool_input":{"path":"/etc/passwd"}}`,
		`{"cwd":"/w","tool_name":"spawn_agent","tool_input":{}}`,
		`{"cwd":"/w","tool_name":"apply_patch","tool_input":{"command":"not a patch"}}`,
	}
	for _, in := range cases {
		actions, err := ParseActions(strings.NewReader(in))
		if err != nil {
			t.Fatal(err)
		}
		if len(actions) != 1 || actions[0].Kind != policy.ActionUnknown {
			t.Errorf("ParseActions(%s) = %+v, want one ActionUnknown", in, actions)
		}
	}
}

func TestParseActionsMalformedInput(t *testing.T) {
	if _, err := ParseActions(strings.NewReader("{not json")); err == nil {
		t.Fatal("want an error for malformed input")
	}
}

func decisionFor(effect policy.Effect) policy.Decision {
	rule := policy.Rule{ID: "test-rule", Description: "test rule fired"}
	return policy.Decision{Effect: effect, Rule: &rule}
}

func decode(t *testing.T, out string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out)
	}
	return m
}

func TestWriteDecision(t *testing.T) {
	cases := []struct {
		name         string
		effect       policy.Effect
		quiet        bool
		wantDecision string // "" = hookSpecificOutput must be absent
		wantMessage  bool
		wantSilence  bool
	}{
		{name: "deny", effect: policy.EffectDeny, wantDecision: "deny", wantMessage: true},
		{name: "ask", effect: policy.EffectAsk, wantDecision: "ask", wantMessage: true},
		{name: "warn is feedback only", effect: policy.EffectWarn, wantMessage: true},
		{name: "allow is feedback only", effect: policy.EffectAllow, wantMessage: true},
		{name: "quiet allow is silent", effect: policy.EffectAllow, quiet: true, wantSilence: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteDecision(&buf, decisionFor(tc.effect), tc.quiet); err != nil {
				t.Fatal(err)
			}
			if tc.wantSilence {
				if buf.Len() != 0 {
					t.Fatalf("want no output, got %s", buf.String())
				}
				return
			}
			m := decode(t, buf.String())
			hso, ok := m["hookSpecificOutput"].(map[string]any)
			if tc.wantDecision == "" {
				if ok {
					// The bypass guard: warn/allow must never carry a decision.
					t.Fatalf("hookSpecificOutput must be absent, got %v", m)
				}
			} else {
				if !ok {
					t.Fatalf("missing hookSpecificOutput in %v", m)
				}
				if hso["hookEventName"] != "PreToolUse" || hso["permissionDecision"] != tc.wantDecision {
					t.Fatalf("hookSpecificOutput = %v, want %s", hso, tc.wantDecision)
				}
				if hso["permissionDecisionReason"] != "test rule fired" {
					t.Fatalf("reason = %v", hso["permissionDecisionReason"])
				}
			}
			msg, _ := m["systemMessage"].(string)
			if tc.wantMessage && (!strings.Contains(msg, "🚧") || !strings.Contains(msg, "test-rule")) {
				t.Fatalf("systemMessage = %q, want the 🚧 notice naming the rule", msg)
			}
		})
	}
}

func TestWriteSessionStart(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSessionStart(&buf, "1.2.3", 2, 24, 1); err != nil {
		t.Fatal(err)
	}
	m := decode(t, buf.String())
	if _, ok := m["hookSpecificOutput"]; ok {
		t.Fatal("the banner must not carry a permission decision")
	}
	msg, _ := m["systemMessage"].(string)
	for _, want := range []string{"Fence v1.2.3", "2 packs", "24 rules", "1 rulepack failed to load"} {
		if !strings.Contains(msg, want) {
			t.Errorf("banner %q missing %q", msg, want)
		}
	}

	buf.Reset()
	if err := WriteSessionStartDegraded(&buf); err != nil {
		t.Fatal(err)
	}
	m = decode(t, buf.String())
	if _, ok := m["hookSpecificOutput"]; ok {
		t.Fatal("the degraded banner must not carry a permission decision")
	}
	if msg, _ := m["systemMessage"].(string); !strings.Contains(msg, "NOT being screened") {
		t.Errorf("degraded banner = %q", msg)
	}
}
