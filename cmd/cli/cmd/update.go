package cmd

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/google/go-github/v84/github"
	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Check for CLI updates",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		ghClient := github.NewClient(nil)

		release, _, err := ghClient.Repositories.GetLatestRelease(ctx, "Nullify-Platform", "cli")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking for updates: %v\n", err)
			os.Exit(1)
		}

		latestVersion := strings.TrimPrefix(release.GetTagName(), "v")
		currentVersion := strings.TrimPrefix(logger.Version, "v")

		if latestVersion == currentVersion || currentVersion == "dev" {
			fmt.Printf("You are running the latest version (%s)\n", logger.Version)
			return
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
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
