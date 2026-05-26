package cmd

import (
	"fmt"
	"net/url"
	"os"
	"strconv"

	"github.com/nullify-platform/cli/internal/logger"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Start cloud scans and inspect scan runs",
	Long:  "Start a cloud scan, check the status of a running scan, and list historical scan runs per scanner type.",
}

var scanStartCmd = &cobra.Command{
	Use:     "start",
	Short:   "Start a cloud scan",
	Example: "  nullify scan start",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger(cmd.Context())
		defer logger.Close(ctx)

		apiClient := getAPIClient()

		result, err := apiClient.CreateContextCloudScanStart(ctx, url.Values{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := output.Print(cmd, result); err != nil {
			fmt.Fprintln(os.Stderr, string(result))
		}
	},
}

var scanStatusCmd = &cobra.Command{
	Use:     "status <scanId>",
	Short:   "Get the status of a cloud scan",
	Args:    cobra.ExactArgs(1),
	Example: "  nullify scan status abc123",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger(cmd.Context())
		defer logger.Close(ctx)

		apiClient := getAPIClient()

		params := url.Values{}
		params.Set("scanId", args[0])

		result, err := apiClient.ListContextCloudScanScanIdStatus(ctx, params)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := output.Print(cmd, result); err != nil {
			fmt.Fprintln(os.Stderr, string(result))
		}
	},
}

var scanRunsCmd = &cobra.Command{
	Use:   "runs",
	Short: "List scan runs for a scanner type",
	Long:  "List historical scan runs for a repository. Use --type to select the scanner (sast, sca, or secrets).",
	Example: "  nullify scan runs --type sast --repository-id repo-123\n" +
		"  nullify scan runs --type sca --repository-id repo-123 --limit 10",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger(cmd.Context())
		defer logger.Close(ctx)

		scanType, _ := cmd.Flags().GetString("type")
		repositoryID, _ := cmd.Flags().GetString("repository-id")
		limit, _ := cmd.Flags().GetInt("limit")

		params := url.Values{}
		params.Set("repositoryId", repositoryID)
		if limit > 0 {
			params.Set("limit", strconv.Itoa(limit))
		}

		apiClient := getAPIClient()

		var result []byte
		var err error
		switch scanType {
		case "sast":
			result, err = apiClient.ListSastScanRuns(ctx, params)
		case "sca":
			result, err = apiClient.ListScaScanRuns(ctx, params)
		case "secrets":
			result, err = apiClient.ListSecretsScanRuns(ctx, params)
		default:
			fmt.Fprintf(os.Stderr, "Error: invalid --type %q (must be one of: sast, sca, secrets)\n", scanType)
			os.Exit(1)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := output.Print(cmd, result); err != nil {
			fmt.Fprintln(os.Stderr, string(result))
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.AddCommand(scanStartCmd)
	scanCmd.AddCommand(scanStatusCmd)
	scanCmd.AddCommand(scanRunsCmd)

	scanRunsCmd.Flags().String("type", "", "Scanner type (sast, sca, secrets)")
	scanRunsCmd.Flags().String("repository-id", "", "Repository ID to list scan runs for")
	scanRunsCmd.Flags().Int("limit", 0, "Maximum number of scan runs to return")
	_ = scanRunsCmd.MarkFlagRequired("type")
	_ = scanRunsCmd.MarkFlagRequired("repository-id")
}
