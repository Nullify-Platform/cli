package cmd

import (
	"os"

	"github.com/nullify-platform/cli/internal/dast"
	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/spf13/cobra"
)

var dastCmd = &cobra.Command{
	Use:   "dast",
	Short: "Test the given app for bugs and vulnerabilities",
	Long:  "Run DAST (Dynamic Application Security Testing) scans against your API endpoints.",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger()
		defer logger.L(ctx).Sync()

		dastArgs := getDastArgs(cmd)

		if dastArgs.Path == "" {
			_ = cmd.Help()
			return
		}

		nullifyClient := getNullifyClient(ctx)

		err := dast.RunDASTScan(ctx, dastArgs, nullifyClient, getLogLevel())
		if err != nil {
			logger.L(ctx).Error(
				"failed to run dast scan",
				logger.Err(err),
			)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(dastCmd)

	dastCmd.Flags().String("app-name", "", "The unique name of the app to be scanned")
	dastCmd.Flags().String("spec-path", "", "The file path to the OpenAPI file (yaml or json)")
	dastCmd.Flags().String("target-host", "", "The base URL of the API to be scanned")
	dastCmd.Flags().StringSlice("header", nil, "Headers for the DAST agent to authenticate with your API")

	dastCmd.Flags().String("github-owner", "", "The GitHub username or organisation")
	dastCmd.Flags().String("github-repo", "", "The repository name for the Nullify issue dashboard")

	dastCmd.Flags().Bool("local", false, "Test the given app locally for bugs and vulnerabilities in private networks")
	dastCmd.Flags().String("image-label", "latest", "Version of the DAST local image used for scanning")
	dastCmd.Flags().Bool("force-pull", false, "Force a docker pull of the latest DAST local image")
	dastCmd.Flags().Bool("use-host-network", false, "Use the host network for the DAST local scan")

	dastCmd.Flags().String("dast-auth-config", "", "The path to the DAST auth config file")
}

func getDastArgs(cmd *cobra.Command) *dast.DAST {
	appName, _ := cmd.Flags().GetString("app-name")
	specPath, _ := cmd.Flags().GetString("spec-path")
	targetHost, _ := cmd.Flags().GetString("target-host")
	headers, _ := cmd.Flags().GetStringSlice("header")
	githubOwner, _ := cmd.Flags().GetString("github-owner")
	githubRepo, _ := cmd.Flags().GetString("github-repo")
	local, _ := cmd.Flags().GetBool("local")
	imageLabel, _ := cmd.Flags().GetString("image-label")
	forcePull, _ := cmd.Flags().GetBool("force-pull")
	useHostNetwork, _ := cmd.Flags().GetBool("use-host-network")
	dastAuthConfig, _ := cmd.Flags().GetString("dast-auth-config")

	return &dast.DAST{
		AppName:          appName,
		Path:             specPath,
		TargetHost:       targetHost,
		AuthHeaders:      headers,
		GitHubOwner:      githubOwner,
		GitHubRepository: githubRepo,
		Local:            local,
		ImageLabel:       imageLabel,
		ForcePullImage:   forcePull,
		UseHostNetwork:   useHostNetwork,
		AuthConfig:       dastAuthConfig,
	}
}
