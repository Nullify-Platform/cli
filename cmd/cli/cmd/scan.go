package cmd

import (
	"context"
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
	Long: "List historical scan runs for a repository. Use --type to select the scanner: " +
		"sast, sca (dependencies, the same as sca_dependencies), sca_containers or secrets.",
	Example: "  nullify scan runs --type sast --repository-id repo-123\n" +
		"  nullify scan runs --type sca --repository-id repo-123 --limit 10\n" +
		"  nullify scan runs --type sca_containers --repository-id repo-123",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		scanType, _ := cmd.Flags().GetString("type")
		repositoryID, _ := cmd.Flags().GetString("repository-id")
		limit, _ := cmd.Flags().GetInt("limit")
		if err := checkScanRunType(scanType); err != nil {
			return err
		}

		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			return err
		}

		result, err := listScanRuns(ctx, authCtx.APIClient(), scanType, repositoryID, limit)
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

// scanRunTypes lists the --type values of `scan runs`.
const scanRunTypes = "sast, sca, sca_dependencies, sca_containers, secrets"

// scaScanTypes maps an SCA --type to the scanType that GET /sca/scan-runs
// requires, since dependency and container scans share that endpoint.
var scaScanTypes = map[string]string{
	"sca":              "sca_dependencies",
	"sca_dependencies": "sca_dependencies",
	"sca_containers":   "sca_containers",
}

func checkScanRunType(scanType string) error {
	if _, sca := scaScanTypes[scanType]; sca || scanType == "sast" || scanType == "secrets" {
		return nil
	}
	return fmt.Errorf("invalid --type %q (must be one of: %s)", scanType, scanRunTypes)
}

// listScanRuns lists one repository's scan runs from the endpoint of the
// scanner type. A limit of 0 leaves the server default.
func listScanRuns(ctx context.Context, c *api.Client, scanType, repositoryID string, limit int) (any, error) {
	if err := checkScanRunType(scanType); err != nil {
		return nil, err
	}
	repoPtr := &repositoryID
	var limitPtr *int
	if limit > 0 {
		limitPtr = &limit
	}

	switch scanType {
	case "sast":
		return c.ListSastScanRuns(ctx, api.ListSastScanRunsInput{RepositoryID: repoPtr, Limit: limitPtr})
	case "secrets":
		return c.ListSecretsScanRuns(ctx, api.ListSecretsScanRunsInput{RepositoryID: repoPtr, Limit: limitPtr})
	default:
		scaType := scaScanTypes[scanType]
		return c.ListScaScanRuns(ctx, api.ListScaScanRunsInput{
			RepositoryID: repoPtr,
			ScanType:     &scaType,
			Limit:        limitPtr,
		})
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.AddCommand(scanStartCmd)
	scanCmd.AddCommand(scanStatusCmd)
	scanCmd.AddCommand(scanRunsCmd)

	scanRunsCmd.Flags().String("type", "", "Scanner type ("+scanRunTypes+")")
	scanRunsCmd.Flags().String("repository-id", "", "Repository ID to list scan runs for")
	scanRunsCmd.Flags().Int("limit", 0, "Maximum number of scan runs to return")
	_ = scanRunsCmd.MarkFlagRequired("type")
	_ = scanRunsCmd.MarkFlagRequired("repository-id")
}
