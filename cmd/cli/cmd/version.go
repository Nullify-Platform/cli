package cmd

import (
	"fmt"
	"runtime"

	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/spf13/cobra"
)

// These are set at build time via ldflags.
var (
	buildCommit = "unknown"
	buildDate   = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show detailed version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Nullify CLI\n")
		fmt.Printf("  Version:    %s\n", logger.Version)
		fmt.Printf("  Commit:     %s\n", buildCommit)
		fmt.Printf("  Built:      %s\n", buildDate)
		fmt.Printf("  Go version: %s\n", runtime.Version())
		fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
