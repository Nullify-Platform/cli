package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/mcp"
	"github.com/nullify-platform/logger/pkg/logger"
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
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger()
		defer logger.L(ctx).Sync()

		mcpHost := resolveHost(ctx)

		token, err := auth.GetValidToken(ctx, mcpHost)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: not authenticated. Run 'nullify auth login' first.\n")
			os.Exit(1)
		}

		creds, err := auth.LoadCredentials()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to load credentials: %v\n", err)
			os.Exit(1)
		}

		hostCreds := creds[mcpHost]

		queryParams := hostCreds.QueryParameters
		if queryParams == nil {
			queryParams = make(map[string]string)
		}

		// Apply --repo flag or auto-detect from git
		repoFlag, _ := cmd.Flags().GetString("repo")
		repo := resolveRepo(repoFlag)
		if repo != "" {
			queryParams["repository"] = repo
		}

		err = mcp.Serve(ctx, mcpHost, token, queryParams)
		if err != nil {
			logger.L(ctx).Error("MCP server error", logger.Err(err))
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.AddCommand(mcpServeCmd)

	mcpServeCmd.Flags().String("repo", "", "Repository name to scope findings to (auto-detected from git remote if not set)")
}

// resolveRepo determines the repository name from the flag or git config.
func resolveRepo(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}

	// Try to auto-detect from .git/config
	return detectRepoFromGit()
}

// detectRepoFromGit reads the git remote origin URL and extracts the repo name.
func detectRepoFromGit() string {
	// Walk up to find .git directory
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}

	for {
		gitConfig := filepath.Join(dir, ".git", "config")
		if _, err := os.Stat(gitConfig); err == nil {
			return parseRepoFromGitConfig(gitConfig)
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return ""
}

// parseRepoFromGitConfig extracts the repo name from a .git/config file.
func parseRepoFromGitConfig(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	inOrigin := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == `[remote "origin"]` {
			inOrigin = true
			continue
		}

		if strings.HasPrefix(line, "[") {
			inOrigin = false
			continue
		}

		if inOrigin && strings.HasPrefix(line, "url") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return extractRepoName(strings.TrimSpace(parts[1]))
			}
		}
	}

	return ""
}

// extractRepoName extracts the repository name from a git remote URL.
// Handles both SSH (git@github.com:org/repo.git) and HTTPS (https://github.com/org/repo.git) formats.
func extractRepoName(remoteURL string) string {
	// Remove trailing .git
	remoteURL = strings.TrimSuffix(remoteURL, ".git")

	// SSH format: git@github.com:org/repo
	if strings.Contains(remoteURL, ":") && strings.HasPrefix(remoteURL, "git@") {
		parts := strings.SplitN(remoteURL, ":", 2)
		if len(parts) == 2 {
			pathParts := strings.Split(parts[1], "/")
			if len(pathParts) > 0 {
				return pathParts[len(pathParts)-1]
			}
		}
	}

	// HTTPS format: https://github.com/org/repo
	parts := strings.Split(remoteURL, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}

	return ""
}
