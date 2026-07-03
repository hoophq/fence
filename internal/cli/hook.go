package cli

import (
	"fmt"
	"io"

	"github.com/hoophq/leash/internal/adapter/claudecode"
	"github.com/spf13/cobra"
)

func newHookCommand(version string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Run as an agent hook (reads a tool call on stdin)",
	}
	cmd.AddCommand(newClaudeCodeHookCommand(version))
	return cmd
}

func newClaudeCodeHookCommand(version string) *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
		Use:   "claude-code",
		Short: "Claude Code PreToolUse hook entrypoint",
		Long: "Reads a Claude Code PreToolUse payload on stdin and writes a permission\n" +
			"decision on stdout. Wire it up with `leash init`, or manually as a\n" +
			"PreToolUse hook running `leash hook claude-code`.\n\n" +
			"Deny/ask/warn decisions include a chat notice (systemMessage) so the\n" +
			"user sees Leash act; with --verbose, allowed calls get a notice too.\n\n" +
			"This command fails open: if anything goes wrong, the tool call is\n" +
			"allowed so the agent is never bricked by Leash.",
		Args: cobra.NoArgs,
		// Disable usage/error noise: a hook's stdout is a machine protocol.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClaudeCodeHook(cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), verbose)
		},
	}
	cmd.Flags().BoolVar(&verbose, "verbose", false,
		"also show a chat notice for allowed tool calls (deny/ask/warn always show one)")
	cmd.AddCommand(newSessionStartHookCommand(version))
	return cmd
}

func newSessionStartHookCommand(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "session-start",
		Short: "Claude Code SessionStart hook entrypoint (prints the session banner)",
		Long: "Writes a SessionStart response whose systemMessage tells the user this\n" +
			"session is guarded by Leash, with the active pack and rule counts.\n" +
			"`leash init` wires it in alongside the PreToolUse hook.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSessionStartHook(cmd.OutOrStdout(), cmd.ErrOrStderr(), version)
		},
	}
}

// runClaudeCodeHook always returns nil (exit 0). It communicates decisions
// through the JSON protocol on out, never through the exit code, and it fails
// open on any internal error.
func runClaudeCodeHook(in io.Reader, out, errw io.Writer, verbose bool) error {
	engine, _, err := buildEngine()
	if err != nil {
		fmt.Fprintf(errw, "leash: failed to load rules, allowing: %v\n", err)
		return nil
	}

	action, err := claudecode.ParseAction(in)
	if err != nil {
		fmt.Fprintf(errw, "leash: could not read tool call, allowing: %v\n", err)
		return nil
	}

	decision := engine.Evaluate(action)

	if err := claudecode.WriteDecision(out, decision, verbose); err != nil {
		fmt.Fprintf(errw, "leash: could not write decision, allowing: %v\n", err)
	}
	return nil
}

// runSessionStartHook always returns nil (exit 0): a banner must never block a
// session from starting. It deliberately does not read stdin — blocking on an
// agent that keeps the pipe open would do exactly that.
func runSessionStartHook(out, errw io.Writer, version string) error {
	engine, failed, err := buildEngine()
	if err != nil {
		fmt.Fprintf(errw, "leash: failed to load rules: %v\n", err)
		if err := claudecode.WriteSessionStartDegraded(out); err != nil {
			fmt.Fprintf(errw, "leash: could not write session banner: %v\n", err)
		}
		return nil
	}
	if err := claudecode.WriteSessionStart(out, version, engine.PackCount(), engine.RuleCount(), failed); err != nil {
		fmt.Fprintf(errw, "leash: could not write session banner: %v\n", err)
	}
	return nil
}
