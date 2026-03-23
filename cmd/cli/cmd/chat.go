package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/nullify-platform/cli/internal/chat"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/spf13/cobra"
)

var chatCmd = &cobra.Command{
	Use:   "chat [message]",
	Short: "Chat with Nullify's AI security agents",
	Long: `Interactive chat with Nullify's AI agents for security assistance.

Without arguments, starts an interactive REPL session.
With a message argument, sends it and streams the response (single-shot mode).

Examples:
  nullify chat                                    # Interactive mode
  nullify chat "what are my critical findings?"   # Single-shot mode
  nullify chat --chat-id abc123 "follow up"       # Resume conversation`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger(cmd.Context())
		defer logger.L(ctx).Sync()

		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			if errors.Is(err, lib.ErrNoToken) {
				fmt.Fprintf(os.Stderr, "Error: not authenticated. Run 'nullify auth login' first.\n")
			} else {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			}
			os.Exit(ExitAuthError)
		}

		// Connect via WebSocket
		conn, err := chat.Dial(ctx, authCtx.Host, authCtx.Token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(ExitNetworkError)
		}

		// Build client options
		var opts []chat.ClientOption

		chatID, _ := cmd.Flags().GetString("chat-id")
		if chatID != "" {
			opts = append(opts, chat.WithChatID(chatID))
		}

		systemPrompt, _ := cmd.Flags().GetString("system-prompt")
		if systemPrompt != "" {
			opts = append(opts, chat.WithSystemPrompt(systemPrompt))
		}

		client := chat.NewClient(conn, authCtx.QueryParams, opts...)
		defer client.Close()

		if len(args) > 0 {
			// Single-shot mode
			message := strings.Join(args, " ")
			if err := chat.RunSingleShot(ctx, client, message); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		} else {
			// Interactive REPL mode
			if err := chat.RunREPL(ctx, client); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}
	},
}

func init() {
	// Note: The generated "chat" command from commands package is registered on rootCmd.
	// This handwritten chat command uses a different name to avoid conflicts.
	// We add it directly since the generated chat commands handle different API endpoints.
	rootCmd.AddCommand(chatCmd)

	chatCmd.Flags().String("system-prompt", "", "Extra system prompt context for the AI agent")
	chatCmd.Flags().String("chat-id", "", "Resume an existing chat conversation by ID")
}
