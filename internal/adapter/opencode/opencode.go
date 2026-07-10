// Package opencode adapts OpenCode's plugin surface to Fence's agent-neutral
// policy model.
//
// OpenCode has no stdin/stdout hook protocol of its own: its extension point
// is a JS plugin (https://opencode.ai/docs/plugins/). `fence init opencode`
// installs a thin shim plugin that pipes each tool call to
// `fence hook opencode` and enforces the decision — so, unlike the Claude
// Code and Codex adapters, Fence owns both ends of this wire. The envelope is
// deliberately minimal: {cwd, tool_name, tool_input} in, {decision, message}
// out. Tool names and argument keys are OpenCode's own (lowercase tools,
// camelCase arguments: bash, edit, write, read, webfetch, apply_patch).
//
// The only block primitive OpenCode's tool.execute.before hook has is
// throwing an error, so the shim throws the message for deny and ask alike —
// ask degrades to a soft block whose message tells the model to get the
// user's confirmation instead of retrying. An explicit "allow" decision is
// never emitted; allow and warn are feedback only.
//
// Fence communicates exclusively through the JSON contract (never via exit
// codes) and fails open: if the input cannot be understood, the tool call
// proceeds as if Fence were not installed.
package opencode

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/hoophq/fence/internal/policy"
)

// hookInput is the envelope the shim sends for each tool call.
type hookInput struct {
	Cwd       string          `json:"cwd"`
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

// toolInput is the union of the OpenCode tool arguments Fence reads.
type toolInput struct {
	Command   string `json:"command"`   // bash
	FilePath  string `json:"filePath"`  // edit/write/read
	Content   string `json:"content"`   // write: full new file content
	NewString string `json:"newString"` // edit: replacement text
	URL       string `json:"url"`       // webfetch
	PatchText string `json:"patchText"` // apply_patch
}

// ParseActions reads a shim payload from r and normalizes it into the neutral
// actions it implies. Most tools map to one action; an apply_patch call
// expands to one file_write per file the patch touches, so path and content
// rules see every file individually. Tool names Fence does not evaluate yield
// a single ActionUnknown action, which the engine allows by default.
func ParseActions(r io.Reader) ([]policy.Action, error) {
	var in hookInput
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return nil, fmt.Errorf("decode hook input: %w", err)
	}

	var ti toolInput
	if len(in.ToolInput) > 0 {
		// Ignore unmarshalling errors for individual fields; missing fields just
		// stay empty and the action degrades to ActionUnknown.
		_ = json.Unmarshal(in.ToolInput, &ti)
	}

	a := policy.Action{Cwd: in.Cwd, Tool: in.ToolName}
	switch in.ToolName {
	case "bash":
		a.Kind = policy.ActionShell
		a.Command = ti.Command
	case "write":
		a.Kind = policy.ActionFileWrite
		a.Path = ti.FilePath
		a.Content = ti.Content
	case "edit":
		a.Kind = policy.ActionFileWrite
		a.Path = ti.FilePath
		// The fragment being introduced, same as the Claude Code adapter's Edit.
		a.Content = ti.NewString
	case "read":
		a.Kind = policy.ActionFileRead
		a.Path = ti.FilePath
	case "webfetch":
		a.Kind = policy.ActionNetFetch
		a.URL = ti.URL
	case "apply_patch":
		if actions := patchActions(in.Cwd, ti.PatchText); len(actions) > 0 {
			return actions, nil
		}
		a.Kind = policy.ActionUnknown
	default:
		a.Kind = policy.ActionUnknown
	}
	return []policy.Action{a}, nil
}

// patchActions extracts one file_write action per file an apply_patch payload
// touches. OpenCode speaks the same Codex-style line-oriented patch format:
//
//	*** Begin Patch
//	*** Add File: path        (following +lines are the new content)
//	*** Update File: path     (following +lines are the text being added)
//	*** Move to: newpath      (optional, after Update File)
//	*** Delete File: path
//	*** End Patch
//
// Content carries only the added lines — the fragment being introduced —
// which is what content-aware rules (manifest_hook) inspect. A patch that
// parses to nothing returns nil and the caller degrades to ActionUnknown.
// The parser is deliberately duplicated from the codex adapter: the two
// formats are owned by different vendors and may drift.
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

// hookOutput is the response envelope the shim reads. Decision is deny, ask
// or warn — never allow, which would be meaningless here (the shim's only
// enforcement primitive is throwing) and is against Fence's rules everywhere:
// Fence only ever tightens. Message is the one-line 🚧 notice; for deny/ask
// it becomes the error the model sees.
type hookOutput struct {
	Decision string `json:"decision,omitempty"`
	Message  string `json:"message,omitempty"`
}

// askGuidance is appended to ask notices. OpenCode cannot surface an approval
// prompt from a plugin, so ask degrades to a soft block; the suffix speaks to
// the model, steering it toward the user instead of into a retry loop.
const askGuidance = " — OpenCode can't show an approval prompt, so the call was not run. " +
	"Don't retry: tell the user what you wanted to run; they can run it themselves " +
	"or allow it in their Fence rules."

// WriteDecision emits the shim response for a decision on w.
//
//   - deny  -> decision "deny" (the shim throws; the tool call never runs)
//   - ask   -> decision "ask"  (the shim throws too — a soft block whose
//     message routes the agent to the user for confirmation)
//   - warn  -> decision "warn"; the shim shows the notice and the action proceeds
//   - allow -> a notice (no decision) confirms Fence looked; with quiet,
//     nothing at all
func WriteDecision(w io.Writer, d policy.Decision, quiet bool) error {
	switch d.Effect {
	case policy.EffectDeny:
		return emit(w, hookOutput{
			Decision: "deny",
			Message:  systemMessage("blocked this", d),
		})
	case policy.EffectAsk:
		return emit(w, hookOutput{
			Decision: "ask",
			Message:  systemMessage("is asking first", d) + askGuidance,
		})
	case policy.EffectWarn:
		return emit(w, hookOutput{
			Decision: "warn",
			Message:  systemMessage("flagged this", d),
		})
	default:
		if quiet {
			return nil
		}
		return emit(w, hookOutput{Message: systemMessage("allowed this", d)})
	}
}

// WriteSessionStart emits the session banner the shim shows as a toast: Fence
// is active — and, when ambient rulepacks failed to load, that the session
// runs with less than the configured protection.
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
	return emit(w, hookOutput{Message: msg})
}

// WriteSessionStartDegraded emits the session banner for the case where the
// rules could not be loaded: the hook fails open, so the honest message is
// that this session is not being screened.
func WriteSessionStartDegraded(w io.Writer) error {
	return emit(w, hookOutput{
		Message: "🚧 Fence could not load its rules — tool calls in this session are NOT being screened (see the OpenCode logs)",
	})
}

func emit(w io.Writer, out hookOutput) error {
	return json.NewEncoder(w).Encode(out)
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
