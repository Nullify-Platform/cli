package commands

import (
	"github.com/nullify-platform/cli/internal/api"
	"github.com/spf13/cobra"
)

// RegisterChatSubcommands adds generated Chat API subcommands to an existing
// parent command (the handwritten chat command) instead of creating a new parent.
func RegisterChatSubcommands(parent *cobra.Command, getClient func() *api.Client) {
	tmp := &cobra.Command{Use: "tmp"}
	RegisterChatCommands(tmp, getClient)

	for _, child := range tmp.Commands() {
		if child.Use == "chat" {
			for _, sub := range child.Commands() {
				parent.AddCommand(sub)
			}
			return
		}
	}
}
