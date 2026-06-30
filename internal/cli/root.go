// Package cli implements the leash command-line interface.
package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hoophq/leash/internal/policy"
	"github.com/spf13/cobra"
)

var rulesFile string

// NewRootCommand builds the root `leash` command and its subcommands.
func NewRootCommand(version string) *cobra.Command {
	root := &cobra.Command{
		Use:   "leash",
		Short: "Guardrails for AI coding agents",
		Long: "Leash keeps AI coding agents from running catastrophic commands —\n" +
			"recursive deletes of your home directory, secret exfiltration, force-\n" +
			"pushes — by inspecting each tool call before it runs. It understands\n" +
			"commands semantically (a real shell parser), so it is not fooled by\n" +
			"flag reordering and does not false-positive on everyday operations.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&rulesFile, "rules", "",
		"path to an additional rulepack (layered on top of the recommended pack)")

	root.AddCommand(
		newCheckCommand(),
		newHookCommand(),
		newInitCommand(),
		newVersionCommand(version),
	)
	return root
}

// buildEngine assembles the policy engine: the embedded recommended pack, plus
// an auto-discovered project rulepack (./.leash.yaml), plus an explicit --rules
// file if given. Later packs layer on top of earlier ones.
func buildEngine() (*policy.Engine, error) {
	packs := []*policy.Rulepack{policy.Recommended()}

	if discovered := discoverProjectRules(); discovered != "" {
		pack, err := policy.LoadFile(discovered)
		if err != nil {
			return nil, err
		}
		packs = append(packs, pack)
	}

	if rulesFile != "" {
		pack, err := policy.LoadFile(rulesFile)
		if err != nil {
			return nil, err
		}
		packs = append(packs, pack)
	}

	return policy.NewEngine(packs...), nil
}

func discoverProjectRules() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	for _, name := range []string{".leash.yaml", ".leash.yml"} {
		candidate := filepath.Join(wd, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func fail(cmd *cobra.Command, err error) error {
	fmt.Fprintf(os.Stderr, "leash: %v\n", err)
	return err
}
