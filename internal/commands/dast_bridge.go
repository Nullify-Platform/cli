package commands

import (
	"github.com/nullify-platform/cli/internal/api"
	"github.com/spf13/cobra"
)

// RegisterDastSubcommands adds generated DAST API subcommands to an existing
// parent command (the handwritten dast command) instead of creating a new parent.
func RegisterDastSubcommands(parent *cobra.Command, getClient func() *api.Client) {
	// Create a temporary parent, register all generated commands onto it,
	// then move its children to the real parent.
	tmp := &cobra.Command{Use: "tmp"}
	RegisterDastCommands(tmp, getClient)

	// The generated function adds a "dast" command to tmp; grab its children.
	for _, child := range tmp.Commands() {
		if child.Use == "dast" {
			for _, sub := range child.Commands() {
				parent.AddCommand(sub)
			}
			return
		}
	}
}
