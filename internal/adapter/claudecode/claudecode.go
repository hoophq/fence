// Package claudecode adapts Claude Code's PreToolUse hook protocol to Leash's
// agent-neutral policy model.
//
// Claude Code invokes a PreToolUse hook with a JSON object on stdin describing
// the tool call, and reads a JSON object on stdout describing the permission
// decision. See https://code.claude.com/docs/en/hooks .
//
// Leash communicates exclusively through that JSON contract (never via exit
// codes) so it can express allow/ask/deny precisely, and it fails open: if the
// input cannot be understood, the tool call proceeds as if Leash were not
// installed. A guardrail must never brick the agent it protects.
package claudecode

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/hoophq/leash/internal/policy"
)

// hookInput is the subset of Claude Code's PreToolUse payload Leash needs.
type hookInput struct {
	Cwd       string          `json:"cwd"`
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

type toolInput struct {
	Command  string `json:"command"`   // Bash
	FilePath string `json:"file_path"` // Write/Edit/MultiEdit/Read/NotebookEdit
	URL      string `json:"url"`       // WebFetch
}

// ParseAction reads a PreToolUse payload from r and normalizes it into a
// policy.Action. Tool names Leash does not evaluate yield an ActionUnknown
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

// hookOutput is the PreToolUse response envelope.
type hookOutput struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// WriteDecision emits the Claude Code response for a decision on w, and returns
// any human-readable note that should be surfaced on stderr (used for "warn",
// which allows the action but informs the user).
//
//   - deny  -> permissionDecision "deny"  (blocks the tool call)
//   - ask   -> permissionDecision "ask"   (forces a user confirmation prompt)
//   - warn  -> no decision emitted; note returned for stderr; action proceeds
//   - allow -> nothing emitted; normal permission flow continues
func WriteDecision(w io.Writer, d policy.Decision) (note string, err error) {
	reason := decisionReason(d)
	switch d.Effect {
	case policy.EffectDeny:
		return "", emit(w, "deny", reason)
	case policy.EffectAsk:
		return "", emit(w, "ask", reason)
	case policy.EffectWarn:
		return reason, nil
	default:
		// allow: stay silent so we don't override the user's own settings.
		return "", nil
	}
}

func emit(w io.Writer, decision, reason string) error {
	out := hookOutput{HookSpecificOutput: hookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       decision,
		PermissionDecisionReason: reason,
	}}
	return json.NewEncoder(w).Encode(out)
}

func decisionReason(d policy.Decision) string {
	if d.Rule == nil {
		return ""
	}
	if d.Rule.Message != "" {
		return d.Rule.Message
	}
	return d.Rule.Description
}
