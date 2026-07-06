package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/hoophq/fence/internal/registry"
	"github.com/hoophq/fence/internal/store"
	"github.com/spf13/cobra"
)

func newUpdateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update [pack...]",
		Short: "Update installed rulepacks to the registry's current versions",
		Long: "Re-reads the registry index and reinstalls any named packs — or every\n" +
			"installed pack — whose published checksum changed. Never removes a pack.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore()
			if err != nil {
				return fail(cmd, err)
			}
			if err := runUpdate(cmd.OutOrStdout(), st, registry.NewClient(registryLocation), args); err != nil {
				return fail(cmd, err)
			}
			return nil
		},
	}
	addRegistryFlag(cmd)
	return cmd
}

func runUpdate(out io.Writer, st *store.Store, client *registry.Client, names []string) error {
	targets, err := updateTargets(st, names)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Fprintln(out, "No packs installed — nothing to update.")
		return nil
	}

	idx, err := fetchIndex(client)
	if err != nil {
		return err
	}
	lf, err := st.Lockfile()
	if err != nil {
		return err
	}

	var failed int
	for _, name := range targets {
		entry, ok := idx.Find(name)
		if !ok {
			fmt.Fprintf(out, "%s: not in this registry (kept as-is)\n", name)
			continue
		}
		locked, managed := lf.Packs[name]
		if !managed {
			fmt.Fprintf(out, "%s: not installed from a registry (kept as-is; fence add %s to adopt it)\n", name, name)
			continue
		}
		// A same-named pack in a different registry is not an update — it is
		// a different pack. Never let one registry replace another's install.
		if locked.Source != client.Location() {
			fmt.Fprintf(out, "%s: installed from a different registry (kept as-is; update with: fence update %s --registry %s)\n",
				name, name, locked.Source)
			continue
		}
		if strings.EqualFold(locked.SHA256, entry.SHA256) {
			fmt.Fprintf(out, "%s %s: up to date\n", name, entry.Version)
			continue
		}
		data, err := client.FetchPack(entry)
		if err != nil {
			fmt.Fprintf(out, "%s: %v (kept at %s)\n", name, err, locked.Version)
			failed++
			continue
		}
		if _, err := st.Install(name, data); err != nil {
			fmt.Fprintf(out, "%s: %v (kept at %s)\n", name, err, locked.Version)
			failed++
			continue
		}
		lf.Packs[name] = store.NewLockEntry(entry.Version, entry.SHA256, client.Location())
		fmt.Fprintf(out, "%s: %s -> %s\n", name, locked.Version, entry.Version)
	}
	if err := st.SaveLockfile(lf); err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("%d pack(s) failed to update", failed)
	}
	return nil
}

// updateTargets resolves what to update: the named packs (each must be
// installed — the user asked for it by name) or everything installed.
func updateTargets(st *store.Store, names []string) ([]string, error) {
	if len(names) == 0 {
		return st.List()
	}
	for _, name := range names {
		if !st.Has(name) {
			return nil, fmt.Errorf("pack %q is not installed", name)
		}
	}
	return names, nil
}
