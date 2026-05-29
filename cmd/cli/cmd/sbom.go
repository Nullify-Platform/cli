package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/logger"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
)

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Retrieve software bill of materials (SBOM) data",
	Long:  "Retrieve SBOM data for a repository. Returns the latest SBOM by default, or a specific project's SBOM when --project-id is provided.",
}

var sbomGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get the SBOM for a repository",
	Example: "  nullify sbom get --repository-id repo-123\n" +
		"  nullify sbom get --repository-id repo-123 --project-id proj-456",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger(cmd.Context())
		defer logger.Close(ctx)

		repositoryID, _ := cmd.Flags().GetString("repository-id")
		projectID, _ := cmd.Flags().GetString("project-id")

		apiClient := getAPIClient()

		var result any
		var err error
		if projectID != "" {
			result, err = apiClient.GetContextSbomsRepositoryRepositoryIdProjectProjectId(ctx, api.GetContextSbomsRepositoryRepositoryIdProjectProjectIdInput{
				RepositoryID: repositoryID,
				ProjectID:    projectID,
			})
		} else {
			result, err = apiClient.ListContextSbomsRepositoryRepositoryIdLatest(ctx, api.ListContextSbomsRepositoryRepositoryIdLatestInput{
				RepositoryID: repositoryID,
			})
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		data, err := json.Marshal(result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := output.Print(cmd, data); err != nil {
			fmt.Fprintln(os.Stderr, string(data))
		}
	},
}

func init() {
	rootCmd.AddCommand(sbomCmd)
	sbomCmd.AddCommand(sbomGetCmd)

	sbomGetCmd.Flags().String("repository-id", "", "Repository ID to retrieve the SBOM for")
	sbomGetCmd.Flags().String("project-id", "", "Project ID for a specific project SBOM (latest repository SBOM if omitted)")
	_ = sbomGetCmd.MarkFlagRequired("repository-id")
}
