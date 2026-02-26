package commands

import (
	"strings"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/spf13/cobra"
)

// RegisterBughuntSubcommands adds generated DAST API subcommands that relate to
// bughunt functionality to the handwritten bughunt command.
func RegisterBughuntSubcommands(parent *cobra.Command, getClient func() *api.Client) {
	tmp := &cobra.Command{Use: "tmp"}
	RegisterDastCommands(tmp, getClient)

	for _, child := range tmp.Commands() {
		if child.Use == "dast" {
			for _, sub := range child.Commands() {
				desc := strings.ToLower(sub.Short)
				if isBughuntCommand(desc) {
					parent.AddCommand(sub)
				}
			}
			return
		}
	}
}

func isBughuntCommand(desc string) bool {
	return strings.Contains(desc, "bughunt") || strings.Contains(desc, "bug hunt")
}
