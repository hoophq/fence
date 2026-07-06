package cli

import (
	"fmt"
	"io"

	"github.com/hoophq/fence/internal/registry"
	"github.com/hoophq/fence/internal/store"
	"github.com/spf13/cobra"
)

func newSearchCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search [query]",
		Short: "Discover rulepacks published in the registry",
		Long: "Lists packs from the registry index, filtered by a query against name,\n" +
			"description, and tags. With no query, lists everything.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := ""
			if len(args) == 1 {
				query = args[0]
			}
			st, _ := openStore() // best-effort: only used to mark installed packs
			if err := runSearch(cmd.OutOrStdout(), st, registry.NewClient(registryLocation), query); err != nil {
				return fail(cmd, err)
			}
			return nil
		},
	}
	addRegistryFlag(cmd)
	return cmd
}

func runSearch(out io.Writer, st *store.Store, client *registry.Client, query string) error {
	idx, err := fetchIndex(client)
	if err != nil {
		return err
	}
	entries := idx.Search(query)
	if len(entries) == 0 {
		if query == "" {
			fmt.Fprintln(out, "The registry has no packs yet.")
		} else {
			fmt.Fprintf(out, "No packs match %q.\n", query)
		}
		return nil
	}

	c := newColors(out)
	for _, e := range entries {
		line := fmt.Sprintf("%s %s", e.Name, e.Version)
		if st != nil && st.Has(e.Name) {
			line += " " + c.dim("(installed)")
		}
		fmt.Fprintln(out, line)
		if e.Description != "" {
			fmt.Fprintf(out, "    %s\n", c.dim(wrap(collapse(e.Description), 72, "    ")))
		}
	}
	fmt.Fprintf(out, "\n%s\n", c.dim("install one with: fence add <pack>"))
	return nil
}
