package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/commands"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
)

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Retrieve software bill of materials (SBOM) data",
	Long:  "Retrieve SBOM data for a repository. Returns the latest SBOM of each project by default, or of one project when --project-id is provided.",
}

var sbomGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get the latest SBOM for a repository",
	Long: "Get the latest SBOM of each project in a repository, or of one project with --project-id.\n\n" +
		"Each document is downloaded through a short-lived link, so a large SBOM is not limited by the API's response size.",
	Example: "  nullify sbom get --repository-id repo-123\n" +
		"  nullify sbom get --repository-id repo-123 --project-id proj-456",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		repositoryID, _ := cmd.Flags().GetString("repository-id")
		projectID, _ := cmd.Flags().GetString("project-id")

		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			return err
		}

		// The document store gets a client of its own, so the API token
		// never goes with a presigned URL.
		download := &http.Client{
			Timeout:   client.HTTPTimeout(),
			Transport: client.NewRetryTransport(http.DefaultTransport),
		}
		result, err := commands.LatestSBOMs(ctx, authCtx.APIClient(), download, repositoryID, projectID)
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

func init() {
	rootCmd.AddCommand(sbomCmd)
	sbomCmd.AddCommand(sbomGetCmd)

	sbomGetCmd.Flags().String("repository-id", "", "Repository ID to retrieve the SBOM for")
	sbomGetCmd.Flags().String("project-id", "", "Project ID to retrieve the latest SBOM for (every project of the repository if omitted)")
	_ = sbomGetCmd.MarkFlagRequired("repository-id")
}
