package cli

import (
	"fmt"
	"io"

	"github.com/hoophq/fence/internal/registry"
	"github.com/hoophq/fence/internal/store"
	"github.com/spf13/cobra"
)

// registryLocation is where the registry commands (add, search, update) read
// the index from — the built-in registry unless --registry overrides it.
var registryLocation string

func addRegistryFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&registryLocation, "registry", registry.DefaultIndexURL,
		"registry index to read (an https URL or a local path)")
}

// openStore returns the user-level store (~/.fence) the registry commands
// operate on. Unlike the engine path, these commands are explicit and loud:
// no store, no command.
func openStore() (*store.Store, error) {
	dir, err := store.DefaultDir()
	if err != nil {
		return nil, err
	}
	return store.Open(dir), nil
}

// fetchIndex reads the registry index, wrapping failures with the one context
// every command wants.
func fetchIndex(client *registry.Client) (*registry.Index, error) {
	idx, err := client.Index()
	if err != nil {
		return nil, fmt.Errorf("fetch registry index: %w", err)
	}
	return idx, nil
}

// writeLock records where an installed pack came from. The lockfile is
// metadata only — a failure here never undoes an install.
func writeLock(st *store.Store, name string, e registry.Entry, source string) error {
	lf, err := st.Lockfile()
	if err != nil {
		return err
	}
	lf.Packs[name] = store.NewLockEntry(e.Version, e.SHA256, source)
	return st.SaveLockfile(lf)
}

// removeLock drops a pack's lockfile entry.
func removeLock(st *store.Store, name string) error {
	lf, err := st.Lockfile()
	if err != nil {
		return err
	}
	delete(lf.Packs, name)
	return st.SaveLockfile(lf)
}

func fprintWarnings(out io.Writer, warnings []string) {
	for _, w := range warnings {
		fmt.Fprintf(out, "note: %s\n", w)
	}
}
