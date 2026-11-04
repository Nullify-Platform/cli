// commandsurface checks the CLI command tree against a committed snapshot, and
// writes a new snapshot when the check passes.
//
// Usage: go run ./scripts/commandsurface [--base <snapshot>] [--write]
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nullify-platform/cli/cmd/cli/cmd"
	"github.com/nullify-platform/cli/internal/commands"
)

const snapshotPath = "spec/command-surface.tsv"

func main() {
	base := flag.String("base", snapshotPath, "snapshot to check the command tree against")
	write := flag.Bool("write", false, "write the snapshot if the check passes")
	flag.Parse()

	if err := run(*base, *write); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(base string, write bool) error {
	content, err := os.ReadFile(base)
	if err != nil {
		return err
	}
	snapshot, err := commands.ParseSurface(string(content))
	if err != nil {
		return err
	}

	live := commands.Surface(cmd.Root())
	if err := commands.CheckSurface(snapshot, live, commands.Decisions); err != nil {
		return err
	}

	if write {
		return os.WriteFile(snapshotPath, []byte(commands.FormatSurface(live)), 0644)
	}
	return nil
}
