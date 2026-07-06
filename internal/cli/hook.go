package cli

import (
	"fmt"
	"io"

	"github.com/hoophq/fence/internal/adapter/claudecode"
	"github.com/hoophq/fence/internal/adapter/codex"
	"github.com/hoophq/fence/internal/policy"
	"github.com/spf13/cobra"
)

func newHookCommand(version string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Run as an agent hook (reads a tool call on stdin)",
	}
	cmd.AddCommand(newClaudeCodeHookCommand(version))
	cmd.AddCommand(newCodexHookCommand(version))
	return cmd
}

func newClaudeCodeHookCommand(version string) *cobra.Command {
	var quiet bool

	cmd := &cobra.Command{
		Use:   "claude-code",
		Short: "Claude Code PreToolUse hook entrypoint",
		Long: "Reads a Claude Code PreToolUse payload on stdin and writes a permission\n" +
			"decision on stdout. Wire it up with `fence init`, or manually as a\n" +
			"PreToolUse hook running `fence hook claude-code`.\n\n" +
			"Deny/ask/warn decisions include a chat notice (systemMessage) so the\n" +
			"user sees Fence act; allowed calls get a notice too unless --quiet.\n\n" +
			"This command fails open: if anything goes wrong, the tool call is\n" +
			"allowed so the agent is never bricked by Fence.",
		Args: cobra.NoArgs,
		// Disable usage/error noise: a hook's stdout is a machine protocol.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClaudeCodeHook(cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), quiet)
		},
	}
	cmd.Flags().BoolVar(&quiet, "quiet", false,
		"don't show a chat notice for allowed tool calls (deny/ask/warn always show one)")
	// --verbose asked for what is now the default. It must stay accepted —
	// silently, with no deprecation chatter on stderr — because settings files
	// written by older `fence init --verbose` runs pass it on every tool call;
	// rejecting it would fail the hook and leave those sessions unguarded.
	cmd.Flags().Bool("verbose", true, "")
	_ = cmd.Flags().MarkHidden("verbose")
	cmd.AddCommand(newSessionStartHookCommand(version))
	return cmd
}

func newSessionStartHookCommand(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "session-start",
		Short: "Claude Code SessionStart hook entrypoint (prints the session banner)",
		Long: "Writes a SessionStart response whose systemMessage tells the user this\n" +
			"session is guarded by Fence, with the active pack and rule counts.\n" +
			"`fence init` wires it in alongside the PreToolUse hook.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSessionStartHook(cmd.OutOrStdout(), cmd.ErrOrStderr(), version)
		},
	}
}

func newCodexHookCommand(version string) *cobra.Command {
	var quiet bool

	cmd := &cobra.Command{
		Use:   "codex",
		Short: "Codex PreToolUse hook entrypoint",
		Long: "Reads a Codex PreToolUse payload on stdin and writes a permission\n" +
			"decision on stdout. Wire it up with `fence init codex`, or manually as\n" +
			"a PreToolUse hook running `fence hook codex`.\n\n" +
			"A Bash call is screened as one shell command; an apply_patch call is\n" +
			"screened per file it touches, and the most severe verdict wins.\n" +
			"Deny/ask/warn decisions include a notice (systemMessage) so the user\n" +
			"sees Fence act; allowed calls get a notice too unless --quiet.\n\n" +
			"This command fails open: if anything goes wrong, the tool call is\n" +
			"allowed so the agent is never bricked by Fence.",
		Args: cobra.NoArgs,
		// Disable usage/error noise: a hook's stdout is a machine protocol.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCodexHook(cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), quiet)
		},
	}
	cmd.Flags().BoolVar(&quiet, "quiet", false,
		"don't show a notice for allowed tool calls (deny/ask/warn always show one)")
	cmd.AddCommand(&cobra.Command{
		Use:           "session-start",
		Short:         "Codex SessionStart hook entrypoint (prints the session banner)",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCodexSessionStartHook(cmd.OutOrStdout(), cmd.ErrOrStderr(), version)
		},
	})
	return cmd
}

// runClaudeCodeHook always returns nil (exit 0). It communicates decisions
// through the JSON protocol on out, never through the exit code, and it fails
// open on any internal error.
func runClaudeCodeHook(in io.Reader, out, errw io.Writer, quiet bool) error {
	engine, _, err := buildEngine()
	if err != nil {
		fmt.Fprintf(errw, "fence: failed to load rules, allowing: %v\n", err)
		return nil
	}

	action, err := claudecode.ParseAction(in)
	if err != nil {
		fmt.Fprintf(errw, "fence: could not read tool call, allowing: %v\n", err)
		return nil
	}

	decision := engine.Evaluate(action)

	if err := claudecode.WriteDecision(out, decision, quiet); err != nil {
		fmt.Fprintf(errw, "fence: could not write decision, allowing: %v\n", err)
	}
	return nil
}

// runCodexHook always returns nil (exit 0), like runClaudeCodeHook. One Codex
// payload can imply several actions (an apply_patch touching many files);
// each is evaluated and the most severe decision wins.
func runCodexHook(in io.Reader, out, errw io.Writer, quiet bool) error {
	engine, _, err := buildEngine()
	if err != nil {
		fmt.Fprintf(errw, "fence: failed to load rules, allowing: %v\n", err)
		return nil
	}

	actions, err := codex.ParseActions(in)
	if err != nil {
		fmt.Fprintf(errw, "fence: could not read tool call, allowing: %v\n", err)
		return nil
	}

	decision := engine.Evaluate(actions[0])
	for _, a := range actions[1:] {
		if d := engine.Evaluate(a); effectRank(d.Effect) > effectRank(decision.Effect) {
			decision = d
		}
	}

	if err := codex.WriteDecision(out, decision, quiet); err != nil {
		fmt.Fprintf(errw, "fence: could not write decision, allowing: %v\n", err)
	}
	return nil
}

// effectRank orders effects by severity for merging multi-action decisions,
// mirroring the engine's deny > ask > warn > allow resolution.
func effectRank(e policy.Effect) int {
	switch e {
	case policy.EffectDeny:
		return 3
	case policy.EffectAsk:
		return 2
	case policy.EffectWarn:
		return 1
	default:
		return 0
	}
}

// runSessionStartHook always returns nil (exit 0): a banner must never block a
// session from starting. It deliberately does not read stdin — blocking on an
// agent that keeps the pipe open would do exactly that.
func runSessionStartHook(out, errw io.Writer, version string) error {
	engine, failed, err := buildEngine()
	if err != nil {
		fmt.Fprintf(errw, "fence: failed to load rules: %v\n", err)
		if err := claudecode.WriteSessionStartDegraded(out); err != nil {
			fmt.Fprintf(errw, "fence: could not write session banner: %v\n", err)
		}
		return nil
	}
	if err := claudecode.WriteSessionStart(out, version, engine.PackCount(), engine.RuleCount(), failed); err != nil {
		fmt.Fprintf(errw, "fence: could not write session banner: %v\n", err)
	}
	return nil
}

// runCodexSessionStartHook is runSessionStartHook speaking the Codex adapter's
// envelope.
func runCodexSessionStartHook(out, errw io.Writer, version string) error {
	engine, failed, err := buildEngine()
	if err != nil {
		fmt.Fprintf(errw, "fence: failed to load rules: %v\n", err)
		if err := codex.WriteSessionStartDegraded(out); err != nil {
			fmt.Fprintf(errw, "fence: could not write session banner: %v\n", err)
		}
		return nil
	}
	if err := codex.WriteSessionStart(out, version, engine.PackCount(), engine.RuleCount(), failed); err != nil {
		fmt.Fprintf(errw, "fence: could not write session banner: %v\n", err)
	}
	return nil
}
