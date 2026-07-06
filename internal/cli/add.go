package cli

import (
	"fmt"
	"io"

	"github.com/hoophq/fence/internal/policy"
	"github.com/hoophq/fence/internal/registry"
	"github.com/hoophq/fence/internal/store"
	"github.com/spf13/cobra"
)

func newAddCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <pack>",
		Short: "Install a rulepack from the registry",
		Long: "Fetches a published rulepack, verifies its checksum against the registry\n" +
			"index, and installs it under ~/.fence/packs. Installed packs layer on the\n" +
			"recommended pack everywhere fence runs — no per-project setup.\n\n" +
			"Discover packs with `fence search`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore()
			if err != nil {
				return fail(cmd, err)
			}
			if err := runAdd(cmd.OutOrStdout(), st, registry.NewClient(registryLocation), args[0]); err != nil {
				return fail(cmd, err)
			}
			return nil
		},
	}
	addRegistryFlag(cmd)
	return cmd
}

func runAdd(out io.Writer, st *store.Store, client *registry.Client, name string) error {
	idx, err := fetchIndex(client)
	if err != nil {
		return err
	}
	entry, ok := idx.Find(name)
	if !ok {
		return fmt.Errorf("pack %q not found in the registry (try: fence search)", name)
	}
	data, err := client.FetchPack(entry)
	if err != nil {
		return err
	}
	pack, err := st.Install(name, data)
	if err != nil {
		return err
	}
	if err := writeLock(st, name, entry, client.Location()); err != nil {
		return err
	}
	fmt.Fprintf(out, "Installed %s %s (%d rules) — active on every tool call from now on.\n",
		name, entry.Version, len(pack.Rules))

	// Surface a missing extends target now, not at the next tool call.
	res := policy.NewResolver(st.Locate)
	if err := res.Add(st.PackPath(name)); err == nil {
		fprintWarnings(out, res.Warnings())
	}
	return nil
}
