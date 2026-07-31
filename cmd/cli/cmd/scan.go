package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/nullify-platform/cli/internal/api"
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
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			return err
		}
		apiClient := authCtx.APIClient()

		result, err := apiClient.CreateContextCloudScanStart(ctx, api.CreateContextCloudScanStartInput{})
		if err != nil {
			return err
		}

		data, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if err := output.Print(cmd, data); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), string(data))
		}
		return nil
	},
}

var scanStatusCmd = &cobra.Command{
	Use:     "status <scanId>",
	Short:   "Get the status of a cloud scan",
	Args:    cobra.ExactArgs(1),
	Example: "  nullify scan status abc123",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			return err
		}
		apiClient := authCtx.APIClient()

		result, err := apiClient.ListContextCloudScanScanIdStatus(ctx, api.ListContextCloudScanScanIdStatusInput{
			ScanID: args[0],
		})
		if err != nil {
			return err
		}

		data, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if err := output.Print(cmd, data); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), string(data))
		}
		return nil
	},
}

var scanRunsCmd = &cobra.Command{
	Use:   "runs",
	Short: "List scan runs for a scanner type",
	Long:  "List historical scan runs for a repository. Use --type to select the scanner (sast, sca, or secrets).",
	Example: "  nullify scan runs --type sast --repository-id repo-123\n" +
		"  nullify scan runs --type sca --repository-id repo-123 --limit 10",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		scanType, _ := cmd.Flags().GetString("type")
		repositoryID, _ := cmd.Flags().GetString("repository-id")
		limit, _ := cmd.Flags().GetInt("limit")

		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			return err
		}
		apiClient := authCtx.APIClient()

		var (
			result any
			apiErr error
		)

		repoPtr := &repositoryID
		var limitPtr *int
		if limit > 0 {
			limitPtr = &limit
		}

		switch scanType {
		case "sast":
			result, apiErr = apiClient.ListSastScanRuns(ctx, api.ListSastScanRunsInput{
				RepositoryID: repoPtr,
				Limit:        limitPtr,
			})
		case "sca":
			result, apiErr = apiClient.ListScaScanRuns(ctx, api.ListScaScanRunsInput{
				RepositoryID: repoPtr,
				Limit:        limitPtr,
			})
		case "secrets":
			result, apiErr = apiClient.ListSecretsScanRuns(ctx, api.ListSecretsScanRunsInput{
				RepositoryID: repoPtr,
				Limit:        limitPtr,
			})
		default:
			return fmt.Errorf("invalid --type %q (must be one of: sast, sca, secrets)", scanType)
		}
		if apiErr != nil {
			return apiErr
		}

		data, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if err := output.Print(cmd, data); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), string(data))
		}
		return nil
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
