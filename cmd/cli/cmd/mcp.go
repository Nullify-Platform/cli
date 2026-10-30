package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/mcp"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "MCP server for AI assistants",
	Long:  "Run Nullify as an MCP (Model Context Protocol) server for use with Claude Code, Cursor, and other AI tools.",
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server",
	Long:  "Start the Nullify MCP server over stdio. Configure your AI tool to run 'nullify mcp serve'.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			return err
		}

		queryParams := authCtx.QueryParams

		// Apply --repo flag or auto-detect from git
		repoFlag, _ := cmd.Flags().GetString("repo")
		repo := resolveRepo(repoFlag)
		if repo != "" {
			queryParams["repository"] = repo
		}

		// Resolve --tools flag
		toolsFlag, _ := cmd.Flags().GetString("tools")
		toolSet := mcp.ToolSet(toolsFlag)
		validSets := mcp.ValidToolSets()
		validSet := false
		for _, v := range validSets {
			if v == toolsFlag {
				validSet = true
				break
			}
		}
		if !validSet {
			return fmt.Errorf("invalid --tools value %q. Valid values: %s", toolsFlag, strings.Join(validSets, ", "))
		}

		apiClient, err := newMCPAPIClient(ctx, authCtx, queryParams)
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}

		err = mcp.ServeWithClient(ctx, apiClient, toolSet)
		if err != nil {
			return fmt.Errorf("MCP server error: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.AddCommand(mcpServeCmd)

	mcpServeCmd.Flags().String("repo", "", "Repository name to scope findings to (auto-detected from git remote if not set)")
	mcpServeCmd.Flags().String("tools", "default", "Tool set to register (default, all, minimal, findings, admin)")
}

// newMCPAPIClient drives the API client through a refreshing, retrying transport so long MCP sessions survive token rotation.
func newMCPAPIClient(ctx context.Context, authCtx *commandAuthContext, queryParams map[string]string) (*api.Client, error) {
	tokenProvider, refreshProvider := mcpTokenProviders(ctx, authCtx.AuthHost)
	httpClient, err := client.NewRefreshingHTTPClient(authCtx.DataHost, tokenProvider, refreshProvider)
	if err != nil {
		return nil, err
	}

	// The refreshing transport sets the Authorization header on every request, so the static token stays empty.
	return api.NewClient(authCtx.DataHost, "", queryParams, api.WithHTTPClient(httpClient)), nil
}

func mcpTokenProviders(ctx context.Context, authHost string) (client.TokenProvider, client.TokenProvider) {
	tokenProvider := func() (string, error) {
		return lib.GetNullifyToken(ctx, authHost, nullifyToken, githubToken)
	}
	refreshProvider := func() (string, error) {
		return lib.RefreshNullifyToken(ctx, authHost, nullifyToken, githubToken)
	}
	return tokenProvider, refreshProvider
}

// resolveRepo determines the repository name from the flag or git config.
func resolveRepo(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}

	return lib.DetectRepoFromGit()
}
