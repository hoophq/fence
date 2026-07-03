package cli

import (
	"fmt"
	"io"

	"github.com/hoophq/leash/internal/store"
	"github.com/spf13/cobra"
)

func newRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <pack>",
		Short: "Uninstall a rulepack installed with `leash add`",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore()
			if err != nil {
				return fail(cmd, err)
			}
			if err := runRemove(cmd.OutOrStdout(), st, args[0]); err != nil {
				return fail(cmd, err)
			}
			return nil
		},
	}
}

func runRemove(out io.Writer, st *store.Store, name string) error {
	if err := st.Remove(name); err != nil {
		return err
	}
	// The pack file is gone — protection already changed. The lockfile is
	// metadata; a problem there is a note, not a failure.
	if err := removeLock(st, name); err != nil {
		fmt.Fprintf(out, "note: could not update lockfile: %v\n", err)
	}
	fmt.Fprintf(out, "Removed %s\n", name)
	return nil
}
