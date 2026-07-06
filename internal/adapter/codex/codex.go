// Package codex adapts OpenAI Codex CLI's hooks protocol to Fence's
// agent-neutral policy model.
//
// Codex invokes a PreToolUse hook with a JSON object on stdin describing the
// tool call and reads a JSON decision on stdout. The envelope is deliberately
// Claude Code-compatible on Codex's side (hookSpecificOutput /
// permissionDecision with allow|deny|ask, systemMessage), but the tool
// vocabulary is Codex's own: shell commands arrive as tool "Bash" with
// {"command": "..."}, and file edits arrive as tool "apply_patch" with the
// whole patch text under the same "command" key. See
// https://developers.openai.com/codex/hooks .
//
// Fence communicates exclusively through the JSON contract (never via exit
// codes) and fails open: if the input cannot be understood, the tool call
// proceeds as if Fence were not installed.
package codex

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/hoophq/fence/internal/policy"
)

// hookInput is the subset of Codex's PreToolUse payload Fence needs.
type hookInput struct {
	Cwd       string          `json:"cwd"`
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

// toolInput carries the one field both Codex tools use: Bash puts the shell
// command there, apply_patch the full patch text.
type toolInput struct {
	Command string `json:"command"`
}

// ParseActions reads a PreToolUse payload from r and normalizes it into the
// neutral actions it implies. A Bash call is one shell action; an apply_patch
// call expands to one file_write per file the patch touches, so path and
// content rules see every file individually. Tool names Fence does not
// evaluate (MCP tools, spawn_agent) yield a single ActionUnknown action,
// which the engine allows by default.
func ParseActions(r io.Reader) ([]policy.Action, error) {
	var in hookInput
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return nil, fmt.Errorf("decode hook input: %w", err)
	}

	var ti toolInput
	if len(in.ToolInput) > 0 {
		// Ignore unmarshalling errors for individual fields; a missing command
		// just degrades the action to ActionUnknown.
		_ = json.Unmarshal(in.ToolInput, &ti)
	}

	switch in.ToolName {
	case "Bash":
		return []policy.Action{{
			Kind:    policy.ActionShell,
			Cwd:     in.Cwd,
			Tool:    in.ToolName,
			Command: ti.Command,
		}}, nil
	case "apply_patch":
		if actions := patchActions(in.Cwd, ti.Command); len(actions) > 0 {
			return actions, nil
		}
	}
	return []policy.Action{{Kind: policy.ActionUnknown, Cwd: in.Cwd, Tool: in.ToolName}}, nil
}

// patchActions extracts one file_write action per file a Codex apply_patch
// payload touches. The patch format is line-oriented:
//
//	*** Begin Patch
//	*** Add File: path        (following +lines are the new content)
//	*** Update File: path     (following +lines are the text being added)
//	*** Move to: newpath      (optional, after Update File)
//	*** Delete File: path
//	*** End Patch
//
// Content carries only the added lines — the fragment being introduced, same
// as the Claude Code adapter does for Edit — which is what content-aware
// rules (manifest_hook) inspect. A patch that parses to nothing returns nil
// and the caller degrades to ActionUnknown.
func patchActions(cwd, patch string) []policy.Action {
	var actions []policy.Action
	var content *strings.Builder

	flush := func() {
		if content == nil {
			return
		}
		actions[len(actions)-1].Content = content.String()
		content = nil
	}
	add := func(path string, withContent bool) {
		flush()
		actions = append(actions, policy.Action{
			Kind: policy.ActionFileWrite,
			Cwd:  cwd,
			Tool: "apply_patch",
			Path: path,
		})
		if withContent {
			content = &strings.Builder{}
		}
	}

	for line := range strings.SplitSeq(patch, "\n") {
		switch {
		case strings.HasPrefix(line, "*** Add File: "):
			add(strings.TrimSpace(strings.TrimPrefix(line, "*** Add File: ")), true)
		case strings.HasPrefix(line, "*** Update File: "):
			add(strings.TrimSpace(strings.TrimPrefix(line, "*** Update File: ")), true)
		case strings.HasPrefix(line, "*** Move to: "):
			// The move target is a path being written; screen it like one.
			add(strings.TrimSpace(strings.TrimPrefix(line, "*** Move to: ")), false)
		case strings.HasPrefix(line, "*** Delete File: "):
			add(strings.TrimSpace(strings.TrimPrefix(line, "*** Delete File: ")), false)
		case strings.HasPrefix(line, "+") && content != nil:
			content.WriteString(line[1:])
			content.WriteByte('\n')
		}
	}
	flush()
	return actions
}

// hookOutput is the hook response envelope. SystemMessage is a line Codex
// shows to the user; HookSpecificOutput carries the permission decision and
// is omitted entirely when Fence has no opinion (warn feedback, allow
// feedback, the session banner).
type hookOutput struct {
	SystemMessage      string              `json:"systemMessage,omitempty"`
	HookSpecificOutput *hookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// WriteDecision emits the Codex response for a decision on w.
//
//   - deny  -> permissionDecision "deny"  (blocks the tool call) + notice
//   - ask   -> permissionDecision "ask"   (forces an approval prompt) + notice
//   - warn  -> no decision emitted; notice only; action proceeds
//   - allow -> a notice (no decision) confirms Fence looked; with quiet,
//     nothing at all
//
// An explicit "allow" decision is never emitted: in Codex it would let the
// call proceed without surfacing the normal approval prompt, bypassing the
// user's own approval policy. Fence only ever tightens.
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

// WriteSessionStart emits the SessionStart response: a banner telling the
// user Fence is active — and, when ambient rulepacks failed to load, that the
// session runs with less than the configured protection.
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
// the rules could not be loaded: the hook fails open, so the honest message
// is that this session is not being screened.
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

// systemMessage builds the one-line notice for a decision, e.g.
// "🚧 Fence is asking first: Force-push detected. … (rule: git-force-push)".
func systemMessage(verb string, d policy.Decision) string {
	// Rule messages may be multi-line YAML blocks; a notice is one line.
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
