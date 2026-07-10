package cli

import (
	"fmt"
	"io"

	"github.com/hoophq/fence/internal/adapter/claudecode"
	"github.com/hoophq/fence/internal/adapter/codex"
	"github.com/hoophq/fence/internal/adapter/opencode"
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
	cmd.AddCommand(newOpencodeHookCommand(version))
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

func newOpencodeHookCommand(version string) *cobra.Command {
	var quiet bool

	cmd := &cobra.Command{
		Use:   "opencode",
		Short: "OpenCode shim-plugin entrypoint",
		Long: "Reads a tool-call payload from the Fence OpenCode plugin on stdin and\n" +
			"writes a decision on stdout. Wire it up with `fence init opencode`,\n" +
			"which installs the plugin that pipes tool calls here.\n\n" +
			"A bash call is screened as one shell command; an apply_patch call is\n" +
			"screened per file it touches, and the most severe verdict wins. The\n" +
			"plugin can only block by throwing, so deny and ask both stop the call;\n" +
			"an ask notice routes the agent to the user for confirmation. Allowed\n" +
			"calls get a notice too unless --quiet.\n\n" +
			"This command fails open: if anything goes wrong, the tool call is\n" +
			"allowed so the agent is never bricked by Fence.",
		Args: cobra.NoArgs,
		// Disable usage/error noise: a hook's stdout is a machine protocol.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runOpencodeHook(cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), quiet)
		},
	}
	cmd.Flags().BoolVar(&quiet, "quiet", false,
		"don't show a notice for allowed tool calls (deny/ask/warn always show one)")
	cmd.AddCommand(&cobra.Command{
		Use:           "session-start",
		Short:         "OpenCode session banner entrypoint (the plugin shows it as a toast)",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runOpencodeSessionStartHook(cmd.OutOrStdout(), cmd.ErrOrStderr(), version)
		},
	})
	return cmd
}

// runAgentHook is the shared PreToolUse flow: parse with one adapter, decide,
// answer with the same adapter. It always returns nil (exit 0), communicates
// decisions through the JSON protocol on out — never through the exit code —
// and fails open on any internal error. One payload can imply several actions
// (a patch touching many files); each is evaluated and the most severe
// decision wins.
func runAgentHook(in io.Reader, out, errw io.Writer, quiet bool,
	parse func(io.Reader) ([]policy.Action, error),
	write func(io.Writer, policy.Decision, bool) error,
) error {
	engine, _, err := buildEngine()
	if err != nil {
		fmt.Fprintf(errw, "fence: failed to load rules, allowing: %v\n", err)
		return nil
	}

	actions, err := parse(in)
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

	if err := write(out, decision, quiet); err != nil {
		fmt.Fprintf(errw, "fence: could not write decision, allowing: %v\n", err)
	}
	return nil
}

func runClaudeCodeHook(in io.Reader, out, errw io.Writer, quiet bool) error {
	return runAgentHook(in, out, errw, quiet, func(r io.Reader) ([]policy.Action, error) {
		a, err := claudecode.ParseAction(r)
		if err != nil {
			return nil, err
		}
		return []policy.Action{a}, nil
	}, claudecode.WriteDecision)
}

func runCodexHook(in io.Reader, out, errw io.Writer, quiet bool) error {
	return runAgentHook(in, out, errw, quiet, codex.ParseActions, codex.WriteDecision)
}

func runOpencodeHook(in io.Reader, out, errw io.Writer, quiet bool) error {
	return runAgentHook(in, out, errw, quiet, opencode.ParseActions, opencode.WriteDecision)
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

// runAgentSessionStartHook is the shared session-banner flow, parameterized
// by one adapter's banner writers. It always returns nil (exit 0): a banner
// must never block a session from starting. It deliberately does not read
// stdin — blocking on an agent that keeps the pipe open would do exactly that.
func runAgentSessionStartHook(out, errw io.Writer, version string,
	writeBanner func(w io.Writer, version string, packs, rules, failed int) error,
	writeDegraded func(io.Writer) error,
) error {
	engine, failed, err := buildEngine()
	if err != nil {
		fmt.Fprintf(errw, "fence: failed to load rules: %v\n", err)
		if err := writeDegraded(out); err != nil {
			fmt.Fprintf(errw, "fence: could not write session banner: %v\n", err)
		}
		return nil
	}
	if err := writeBanner(out, version, engine.PackCount(), engine.RuleCount(), failed); err != nil {
		fmt.Fprintf(errw, "fence: could not write session banner: %v\n", err)
	}
	return nil
}

func runSessionStartHook(out, errw io.Writer, version string) error {
	return runAgentSessionStartHook(out, errw, version,
		claudecode.WriteSessionStart, claudecode.WriteSessionStartDegraded)
}

func runCodexSessionStartHook(out, errw io.Writer, version string) error {
	return runAgentSessionStartHook(out, errw, version,
		codex.WriteSessionStart, codex.WriteSessionStartDegraded)
}

func runOpencodeSessionStartHook(out, errw io.Writer, version string) error {
	return runAgentSessionStartHook(out, errw, version,
		opencode.WriteSessionStart, opencode.WriteSessionStartDegraded)
}
