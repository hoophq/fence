// Command fence is the Fence CLI: guardrails for AI coding agents.
package main

import (
	"os"

	"github.com/hoophq/fence/internal/cli"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := cli.NewRootCommand(version).Execute(); err != nil {
		os.Exit(1)
	}
}
