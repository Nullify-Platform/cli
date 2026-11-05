// commandsurface checks the CLI command tree and the MCP tools against committed
// snapshots, and writes new snapshots when the check passes.
//
// Usage: go run ./scripts/commandsurface [--base <snapshot>] [--base-tools <snapshot>] [--write]
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nullify-platform/cli/cmd/cli/cmd"
	"github.com/nullify-platform/cli/internal/commands"
	"github.com/nullify-platform/cli/internal/mcp"
)

const (
	snapshotPath     = "spec/command-surface.tsv"
	toolSnapshotPath = "spec/mcp-tools.tsv"
)

func main() {
	base := flag.String("base", snapshotPath, "snapshot to check the command tree against")
	baseTools := flag.String("base-tools", toolSnapshotPath, "snapshot to check the MCP tools against")
	write := flag.Bool("write", false, "write the snapshots if the check passes")
	flag.Parse()

	if err := run(*base, *baseTools, *write); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(base, baseTools string, write bool) error {
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

	toolContent, err := os.ReadFile(baseTools)
	if err != nil {
		return err
	}
	toolSnapshot, err := mcp.ParseToolSurface(string(toolContent))
	if err != nil {
		return err
	}
	liveTools := mcp.ToolSurface()
	if err := mcp.CheckToolSurface(toolSnapshot, liveTools, mcp.Decisions); err != nil {
		return err
	}

	if !write {
		return nil
	}
	if err := os.WriteFile(snapshotPath, []byte(commands.FormatSurface(live)), 0644); err != nil {
		return err
	}
	return os.WriteFile(toolSnapshotPath, []byte(mcp.FormatToolSurface(liveTools)), 0644)
}
