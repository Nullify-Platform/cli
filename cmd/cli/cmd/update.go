package cmd

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/google/go-github/v85/github"
	"github.com/nullify-platform/cli/internal/logger"
	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Check for CLI updates",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		ghClient := github.NewClient(nil)

		release, _, err := ghClient.Repositories.GetLatestRelease(ctx, "Nullify-Platform", "cli")
		if err != nil {
			return fmt.Errorf("checking for updates: %w", err)
		}

		latestVersion := strings.TrimPrefix(release.GetTagName(), "v")
		currentVersion := strings.TrimPrefix(logger.Version, "v")

		if latestVersion == currentVersion || currentVersion == "dev" {
			fmt.Printf("You are running the latest version (%s)\n", logger.Version)
			return nil
		}

		fmt.Printf("A new version is available: %s (current: %s)\n\n", latestVersion, logger.Version)
		fmt.Println("Upgrade instructions:")
		fmt.Println()

		switch runtime.GOOS {
		case "darwin":
			fmt.Println("  # Homebrew")
			fmt.Println("  brew upgrade nullify-platform/tap/nullify")
			fmt.Println()
		}

		fmt.Println("  # Direct download")
		fmt.Printf("  curl -sSL https://github.com/Nullify-Platform/cli/releases/download/v%s/nullify_%s_%s.tar.gz | tar xz\n",
			latestVersion, runtime.GOOS, runtime.GOARCH)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
