// Package cli implements the fence command-line interface.
package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/hoophq/fence/internal/policy"
	"github.com/hoophq/fence/internal/store"
	"github.com/spf13/cobra"
)

var rulesFile string

// NewRootCommand builds the root `fence` command and its subcommands.
func NewRootCommand(version string) *cobra.Command {
	root := &cobra.Command{
		Use:   "fence",
		Short: "Guardrails for AI coding agents",
		Long: "Fence keeps AI coding agents from running catastrophic commands —\n" +
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
		newHookCommand(version),
		newInitCommand(),
		newUninstallCommand(),
		newAddCommand(),
		newSearchCommand(),
		newRemoveCommand(),
		newUpdateCommand(),
		newVersionCommand(version),
	)
	return root
}

// buildEngine assembles the policy engine: the embedded recommended pack, the
// packs installed with `fence add` (~/.fence/packs), an auto-discovered
// project rulepack (./.fence.yaml), and an explicit --rules file if given.
// Later packs layer on top of earlier ones, and any pack can pull others in
// with extends:.
func buildEngine() (*policy.Engine, int, error) {
	var st *store.Store
	dir, err := store.DefaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fence: skipping installed packs: %v\n", err)
	} else {
		st = store.Open(dir)
	}
	return buildEngineWithStore(st, rulesFile, os.Stderr)
}

// buildEngineWithStore is buildEngine with its inputs injected for tests.
// Ambient sources — installed packs and the discovered .fence.yaml — degrade:
// one that fails to load is skipped with a warning so the rest keep
// protecting. The int returned counts those skipped sources, so the session
// banner can say protection is thinner than configured. The explicit --rules
// file stays a hard error: the user asked for it by name.
func buildEngineWithStore(st *store.Store, rulesFile string, errw io.Writer) (*policy.Engine, int, error) {
	res := policy.NewResolver(locator(st))
	var warnings []string
	failed := 0

	if st != nil {
		names, err := st.List()
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("reading installed packs: %v (skipped)", err))
			failed++
		}
		for _, name := range names {
			path, ok := st.Locate(name)
			if !ok {
				continue
			}
			if err := res.Add(path); err != nil {
				warnings = append(warnings, fmt.Sprintf("installed pack %q: %v (skipped)", name, err))
				failed++
			}
		}
	}

	if discovered := discoverProjectRules(); discovered != "" {
		if err := res.Add(discovered); err != nil {
			warnings = append(warnings, fmt.Sprintf("%v (skipped)", err))
			failed++
		}
	}

	if rulesFile != "" {
		if err := res.Add(rulesFile); err != nil {
			return nil, 0, err
		}
	}

	packs := append([]*policy.Rulepack{policy.Recommended()}, res.Packs()...)
	engine := policy.NewEngine(packs...)
	warnings = append(warnings, res.Warnings()...)
	warnings = append(warnings, engine.Warnings()...)
	for _, w := range warnings {
		fmt.Fprintf(errw, "fence: %s\n", w)
	}
	return engine, failed, nil
}

// locator adapts a possibly-nil store to a policy.LocateFunc.
func locator(st *store.Store) policy.LocateFunc {
	if st == nil {
		return nil
	}
	return st.Locate
}

func discoverProjectRules() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	for _, name := range []string{".fence.yaml", ".fence.yml"} {
		candidate := filepath.Join(wd, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func fail(cmd *cobra.Command, err error) error {
	fmt.Fprintf(os.Stderr, "fence: %v\n", err)
	return err
}
