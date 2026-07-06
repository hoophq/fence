// Package claudecode adapts Claude Code's PreToolUse hook protocol to Fence's
// agent-neutral policy model.
//
// Claude Code invokes a PreToolUse hook with a JSON object on stdin describing
// the tool call, and reads a JSON object on stdout describing the permission
// decision. See https://code.claude.com/docs/en/hooks .
//
// Fence communicates exclusively through that JSON contract (never via exit
// codes) so it can express allow/ask/deny precisely, and it fails open: if the
// input cannot be understood, the tool call proceeds as if Fence were not
// installed. A guardrail must never brick the agent it protects.
package claudecode

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/hoophq/fence/internal/policy"
)

// hookInput is the subset of Claude Code's PreToolUse payload Fence needs.
type hookInput struct {
	Cwd       string          `json:"cwd"`
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

type toolInput struct {
	Command   string `json:"command"`    // Bash
	FilePath  string `json:"file_path"`  // Write/Edit/MultiEdit/Read/NotebookEdit
	URL       string `json:"url"`        // WebFetch
	Content   string `json:"content"`    // Write: full new file content
	NewString string `json:"new_string"` // Edit: replacement text
	Edits     []struct {
		NewString string `json:"new_string"`
	} `json:"edits"` // MultiEdit: sequence of replacements
}

// ParseAction reads a PreToolUse payload from r and normalizes it into a
// policy.Action. Tool names Fence does not evaluate yield an ActionUnknown
// action, which the engine allows by default.
func ParseAction(r io.Reader) (policy.Action, error) {
	var in hookInput
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return policy.Action{}, fmt.Errorf("decode hook input: %w", err)
	}

	var ti toolInput
	if len(in.ToolInput) > 0 {
		// Ignore unmarshalling errors for individual fields; missing fields just
		// stay empty and the action degrades to ActionUnknown.
		_ = json.Unmarshal(in.ToolInput, &ti)
	}

	a := policy.Action{Cwd: in.Cwd, Tool: in.ToolName}
	switch in.ToolName {
	case "Bash":
		a.Kind = policy.ActionShell
		a.Command = ti.Command
	case "Write", "Edit", "MultiEdit", "NotebookEdit":
		a.Kind = policy.ActionFileWrite
		a.Path = ti.FilePath
		a.Content = writeContent(in.ToolName, ti)
	case "Read":
		a.Kind = policy.ActionFileRead
		a.Path = ti.FilePath
	case "WebFetch":
		a.Kind = policy.ActionNetFetch
		a.URL = ti.URL
	default:
		a.Kind = policy.ActionUnknown
	}
	return a, nil
}

// writeContent returns the new text a file-editing tool will introduce, for
// content-aware rules. For Write it is the whole file; for Edit/MultiEdit it is
// the replacement text (the fragment being added), which need not be valid on
// its own.
func writeContent(tool string, ti toolInput) string {
	switch tool {
	case "Write":
		return ti.Content
	case "Edit":
		return ti.NewString
	case "MultiEdit":
		var b strings.Builder
		for _, e := range ti.Edits {
			b.WriteString(e.NewString)
			b.WriteByte('\n')
		}
		return b.String()
	}
	return ""
}

// hookOutput is the hook response envelope. SystemMessage is a line Claude
// Code shows to the user in the chat; HookSpecificOutput carries the
// permission decision and is omitted entirely when Fence has no opinion
// (warn feedback, allow feedback, the session banner).
type hookOutput struct {
	SystemMessage      string              `json:"systemMessage,omitempty"`
	HookSpecificOutput *hookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// WriteDecision emits the Claude Code response for a decision on w.
//
//   - deny  -> permissionDecision "deny"  (blocks the tool call) + chat notice
//   - ask   -> permissionDecision "ask"   (forces a user confirmation prompt) + chat notice
//   - warn  -> no decision emitted; chat notice only; action proceeds
//   - allow -> a chat notice (no decision) confirms Fence looked, so the
//     user's own permission flow is untouched; with quiet, nothing at all
//
// Emitting an explicit "allow" decision would auto-approve the call and bypass
// the user's permission settings, so Fence never does — the allow notice is
// feedback only.
func WriteDecision(w io.Writer, d policy.Decision, quiet bool) error {
	switch d.Effect {
	case policy.EffectDeny:
		return emit(w, hookOutput{
			SystemMessage:      systemMessage("blocked this", d),
			HookSpecificOutput: preToolUse("deny", decisionReason(d)),
		})
	case policy.EffectAsk:
		return emit(w, hookOutput{
			SystemMessage:      systemMessage("is asking first", d),
			HookSpecificOutput: preToolUse("ask", decisionReason(d)),
		})
	case policy.EffectWarn:
		return emit(w, hookOutput{SystemMessage: systemMessage("flagged this", d)})
	default:
		if quiet {
			return nil
		}
		return emit(w, hookOutput{SystemMessage: systemMessage("allowed this", d)})
	}
}

// WriteSessionStart emits the SessionStart response: a banner telling the user
// Fence is active — and, when ambient rulepacks failed to load, that the
// session runs with less than the configured protection. It carries no
// permission decision and adds nothing to the model's context (plain stdout on
// SessionStart would).
func WriteSessionStart(w io.Writer, version string, packs, rules, failed int) error {
	name := "Fence"
	if version != "" {
		if version[0] >= '0' && version[0] <= '9' {
			version = "v" + version
		}
		name += " " + version
	}
	msg := fmt.Sprintf("🚧 %s is guarding this session (%s, %s)",
		name, plural(packs, "pack"), plural(rules, "rule"))
	if failed > 0 {
		msg += fmt.Sprintf(" — ⚠️ %s failed to load", plural(failed, "rulepack"))
	}
	return emit(w, hookOutput{SystemMessage: msg})
}

// WriteSessionStartDegraded emits the SessionStart banner for the case where
// the rules could not be loaded: the hook fails open, so the honest message is
// that this session is not being screened.
func WriteSessionStartDegraded(w io.Writer) error {
	return emit(w, hookOutput{
		SystemMessage: "🚧 Fence could not load its rules — tool calls in this session are NOT being screened (see stderr in the transcript)",
	})
}

func emit(w io.Writer, out hookOutput) error {
	return json.NewEncoder(w).Encode(out)
}

func preToolUse(decision, reason string) *hookSpecificOutput {
	return &hookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       decision,
		PermissionDecisionReason: reason,
	}
}

// systemMessage builds the one-line chat notice for a decision, e.g.
// "🚧 Fence is asking first: Force-push detected. … (rule: git-force-push)".
func systemMessage(verb string, d policy.Decision) string {
	// Rule messages may be multi-line YAML blocks; a chat notice is one line.
	reason := strings.Join(strings.Fields(decisionReason(d)), " ")

	var b strings.Builder
	b.WriteString("🚧 ")
	switch {
	case reason == "":
		b.WriteString("Fence ")
		b.WriteString(verb)
	// Many rule messages already speak as Fence ("Fence blocked a recursive
	// delete …"); prefixing the verb again would stutter.
	case len(reason) >= 6 && strings.EqualFold(reason[:6], "fence "):
		b.WriteString(reason)
	default:
		b.WriteString("Fence ")
		b.WriteString(verb)
		b.WriteString(": ")
		b.WriteString(reason)
	}
	if d.Rule != nil && d.Rule.ID != "" {
		fmt.Fprintf(&b, " (rule: %s)", d.Rule.ID)
	}
	return b.String()
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func decisionReason(d policy.Decision) string {
	if d.Rule == nil {
		return ""
	}
	return d.Rule.Text()
}
