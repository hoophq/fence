package opencode

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hoophq/fence/internal/policy"
)

func TestParseActionsToolMapping(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want policy.Action
	}{
		{
			name: "bash",
			in:   `{"cwd":"/w","tool_name":"bash","tool_input":{"command":"rm -rf ~"}}`,
			want: policy.Action{Kind: policy.ActionShell, Command: "rm -rf ~", Cwd: "/w", Tool: "bash"},
		},
		{
			name: "write carries the full content",
			in:   `{"cwd":"/w","tool_name":"write","tool_input":{"filePath":"a.txt","content":"hello"}}`,
			want: policy.Action{Kind: policy.ActionFileWrite, Path: "a.txt", Content: "hello", Cwd: "/w", Tool: "write"},
		},
		{
			name: "edit carries the replacement fragment",
			in:   `{"cwd":"/w","tool_name":"edit","tool_input":{"filePath":"a.txt","oldString":"x","newString":"y"}}`,
			want: policy.Action{Kind: policy.ActionFileWrite, Path: "a.txt", Content: "y", Cwd: "/w", Tool: "edit"},
		},
		{
			name: "read",
			in:   `{"cwd":"/w","tool_name":"read","tool_input":{"filePath":"/etc/passwd"}}`,
			want: policy.Action{Kind: policy.ActionFileRead, Path: "/etc/passwd", Cwd: "/w", Tool: "read"},
		},
		{
			name: "webfetch",
			in:   `{"cwd":"/w","tool_name":"webfetch","tool_input":{"url":"https://x.test/a"}}`,
			want: policy.Action{Kind: policy.ActionNetFetch, URL: "https://x.test/a", Cwd: "/w", Tool: "webfetch"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actions, err := ParseActions(strings.NewReader(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if len(actions) != 1 {
				t.Fatalf("got %d actions, want 1", len(actions))
			}
			if actions[0] != tc.want {
				t.Fatalf("action = %+v, want %+v", actions[0], tc.want)
			}
		})
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
		"tool_input": map[string]string{"patchText": patch},
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
		`{"cwd":"/w","tool_name":"glob","tool_input":{"pattern":"**/*.go"}}`,
		`{"cwd":"/w","tool_name":"todowrite","tool_input":{}}`,
		`{"cwd":"/w","tool_name":"apply_patch","tool_input":{"patchText":"not a patch"}}`,
		// Casing is OpenCode's, not Claude Code's: "Bash" is not a tool here.
		`{"cwd":"/w","tool_name":"Bash","tool_input":{"command":"rm -rf ~"}}`,
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
		wantDecision string // "" = the decision field must be absent
		wantSilence  bool
	}{
		{name: "deny", effect: policy.EffectDeny, wantDecision: "deny"},
		{name: "ask", effect: policy.EffectAsk, wantDecision: "ask"},
		{name: "warn", effect: policy.EffectWarn, wantDecision: "warn"},
		{name: "allow is feedback only", effect: policy.EffectAllow},
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
			decision, _ := m["decision"].(string)
			if decision != tc.wantDecision {
				// The bypass guard: allow must never carry a decision the shim
				// could act on, and deny/ask/warn must carry the right one.
				t.Fatalf("decision = %q, want %q in %v", decision, tc.wantDecision, m)
			}
			msg, _ := m["message"].(string)
			if !strings.Contains(msg, "🚧") || !strings.Contains(msg, "test-rule") {
				t.Fatalf("message = %q, want the 🚧 notice naming the rule", msg)
			}
		})
	}
}

// The ask message must route the model to the user, not into a retry loop:
// the shim can only throw, so a bare "asking first" would invite the agent to
// try the same call again forever.
func TestWriteDecisionAskCarriesGuidance(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteDecision(&buf, decisionFor(policy.EffectAsk), false); err != nil {
		t.Fatal(err)
	}
	msg, _ := decode(t, buf.String())["message"].(string)
	for _, want := range []string{"Don't retry", "tell the user"} {
		if !strings.Contains(msg, want) {
			t.Errorf("ask message %q missing %q", msg, want)
		}
	}
}

func TestWriteSessionStart(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSessionStart(&buf, "1.2.3", 2, 24, 1); err != nil {
		t.Fatal(err)
	}
	m := decode(t, buf.String())
	if _, ok := m["decision"]; ok {
		t.Fatal("the banner must not carry a decision")
	}
	msg, _ := m["message"].(string)
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
	if _, ok := m["decision"]; ok {
		t.Fatal("the degraded banner must not carry a decision")
	}
	if msg, _ := m["message"].(string); !strings.Contains(msg, "NOT being screened") {
		t.Errorf("degraded banner = %q", msg)
	}
}
