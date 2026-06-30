package cli

import (
	"fmt"
	"os"

	"github.com/hoophq/leash/internal/adapter/claudecode"
	"github.com/spf13/cobra"
)

func newHookCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Run as an agent hook (reads a tool call on stdin)",
	}
	cmd.AddCommand(newClaudeCodeHookCommand())
	return cmd
}

func newClaudeCodeHookCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "claude-code",
		Short: "Claude Code PreToolUse hook entrypoint",
		Long: "Reads a Claude Code PreToolUse payload on stdin and writes a permission\n" +
			"decision on stdout. Wire it up with `leash init`, or manually as a\n" +
			"PreToolUse hook running `leash hook claude-code`.\n\n" +
			"This command fails open: if anything goes wrong, the tool call is\n" +
			"allowed so the agent is never bricked by Leash.",
		Args: cobra.NoArgs,
		// Disable usage/error noise: a hook's stdout is a machine protocol.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClaudeCodeHook()
		},
	}
}

// runClaudeCodeHook always returns nil (exit 0). It communicates decisions
// through the JSON protocol on stdout, never through the exit code, and it
// fails open on any internal error.
func runClaudeCodeHook() error {
	engine, err := buildEngine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "leash: failed to load rules, allowing: %v\n", err)
		return nil
	}

	action, err := claudecode.ParseAction(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leash: could not read tool call, allowing: %v\n", err)
		return nil
	}

	decision := engine.Evaluate(action)

	note, err := claudecode.WriteDecision(os.Stdout, decision)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leash: could not write decision, allowing: %v\n", err)
		return nil
	}
	if note != "" {
		fmt.Fprintf(os.Stderr, "leash: %s\n", note)
	}
	return nil
}
