package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/auth"
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
	Long: "Start the Nullify MCP server over stdio. Configure your AI tool to run 'nullify mcp serve'. " +
		"When your login covers several organizations, tools take an optional org argument; --org sets the default.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		repoFlag, _ := cmd.Flags().GetString("repo")
		toolsFlag, _ := cmd.Flags().GetString("tools")
		apiClient, toolSet, orgs, err := mcpServeConfig(ctx, repoFlag, toolsFlag)
		if err != nil {
			return err
		}

		if err := mcp.ServeWithClient(ctx, apiClient, toolSet, orgs); err != nil {
			return fmt.Errorf("MCP server error: %w", err)
		}
		return nil
	},
}

// mcpServeConfig resolves auth, never an org: a login may cover several
// orgs, and each tool call picks one (its org argument, then serve --org,
// then the usual chain).
func mcpServeConfig(ctx context.Context, repoFlag, toolsFlag string) (*api.Client, mcp.ToolSet, mcp.Orgs, error) {
	authCtx, err := resolveCommandToken(ctx)
	if err != nil {
		return nil, "", mcp.Orgs{}, err
	}

	queryParams := map[string]string{}
	if repo := resolveRepo(repoFlag); repo != "" {
		queryParams["repository"] = repo
	}

	toolSet := mcp.ToolSet(toolsFlag)
	if !slices.Contains(mcp.ValidToolSets(), toolsFlag) {
		return nil, "", mcp.Orgs{}, fmt.Errorf("invalid --tools value %q. Valid values: %s", toolsFlag, strings.Join(mcp.ValidToolSets(), ", "))
	}

	// Drive the generated API client through a refreshing+retrying transport
	// so long-running MCP sessions keep working as the token rotates; the
	// token is refreshed wherever the login lives (the router, for a router
	// tenant). Each call's org scope is set by ScopeTransport.
	tokenProvider := func() (string, error) {
		return lib.GetNullifyToken(ctx, authCtx.Host, nullifyToken, githubToken)
	}
	refreshProvider := func() (string, error) {
		return lib.RefreshNullifyToken(ctx, authCtx.Host, nullifyToken, githubToken)
	}
	refreshing, err := client.NewRefreshingHTTPClient(authCtx.Host, tokenProvider, refreshProvider)
	if err != nil {
		return nil, "", mcp.Orgs{}, fmt.Errorf("failed to create client: %w", err)
	}
	httpClient := &http.Client{
		Timeout:       refreshing.Timeout,
		Transport:     mcp.ScopeTransport(refreshing.Transport),
		CheckRedirect: refreshing.CheckRedirect,
	}
	// Empty token literal is intentional: the refreshing transport's
	// RoundTrip injects (and rotates) the Authorization header after
	// api.Client.do sets it, so the static value in api.Client is
	// overridden on every request.
	apiClient := api.NewClient(authCtx.Host, "", queryParams, api.WithHTTPClient(httpClient))

	serveOrg := orgFlag
	orgs := mcp.Orgs{
		Resolve: func(ctx context.Context, org string) (map[string]string, error) {
			flag, source := serveOrg, "--org"
			if org != "" {
				flag, source = org, "org argument"
			}
			token, err := tokenProvider()
			if err != nil {
				return nil, err
			}
			scope, err := resolveOrgScope(ctx, authCtx.Host, token, orgInputsFor(authCtx.Host, flag, source), false)
			var notChosen *auth.ErrOrgNotChosen
			if errors.As(err, &notChosen) {
				choices := make([]string, len(notChosen.Orgs))
				for i, o := range notChosen.Orgs {
					choices[i] = o.String()
				}
				return nil, fmt.Errorf("%s serves several of your organizations; pass the org argument (name or id), "+
					"or start the server with --org: %s", authCtx.Host, strings.Join(choices, ", "))
			}
			if err != nil {
				return nil, err
			}
			return scope.Query, nil
		},
		List: func(ctx context.Context) (any, error) {
			token, err := tokenProvider()
			if err != nil {
				return nil, err
			}
			return orgListing(ctx, authCtx.Host, token, serveOrg)
		},
	}

	return apiClient, toolSet, orgs, nil
}

func init() {
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.AddCommand(mcpServeCmd)

	mcpServeCmd.Flags().String("repo", "", "Repository name to scope findings to (auto-detected from git remote if not set)")
	mcpServeCmd.Flags().String("tools", "default", "Tool set to register (default, all, minimal, findings, admin)")
}

// resolveRepo determines the repository name from the flag or git config.
func resolveRepo(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}

	return lib.DetectRepoFromGit()
}
