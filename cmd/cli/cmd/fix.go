package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/spf13/cobra"
)

var fixCmd = &cobra.Command{
	Use:   "fix <finding-id>",
	Short: "Generate an autofix for a finding",
	Long: `Generate an automated fix for a security finding and optionally create a PR.

Supports SAST and SCA dependency findings.`,
	Example: `  # Fix a SAST finding
  nullify fix abc123 --type sast

  # Fix and create a PR
  nullify fix abc123 --type sast --create-pr

  # Fix an SCA dependency finding
  nullify fix def456 --type sca`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger()
		defer logger.L(ctx).Sync()

		findingID := args[0]

		fixHost := resolveHost(ctx)
		token, err := lib.GetNullifyToken(ctx, fixHost, nullifyToken, githubToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: not authenticated. Run 'nullify auth login' first.\n")
			os.Exit(1)
		}

		nullifyClient := client.NewNullifyClient(fixHost, token)

		creds, err := auth.LoadCredentials()
		queryParams := map[string]string{}
		if err == nil {
			if hostCreds, ok := creds[fixHost]; ok && hostCreds.QueryParameters != nil {
				queryParams = hostCreds.QueryParameters
			}
		}

		findingType, _ := cmd.Flags().GetString("type")
		createPR, _ := cmd.Flags().GetBool("create-pr")

		var basePath string
		switch findingType {
		case "sast":
			basePath = "/sast/findings"
		case "sca":
			basePath = "/sca/dependencies/findings"
		default:
			fmt.Fprintf(os.Stderr, "Error: --type must be 'sast' or 'sca'\n")
			os.Exit(1)
		}

		qs := lib.BuildQueryString(queryParams)

		// Step 1: Generate autofix
		if !quiet {
			fmt.Fprintf(os.Stderr, "Generating fix for %s finding %s...\n", findingType, findingID)
		}
		_, err = lib.DoGet(ctx, nullifyClient.HttpClient, nullifyClient.BaseURL,
			fmt.Sprintf("%s/%s/autofix/fix%s", basePath, findingID, qs))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating fix: %v\n", err)
			os.Exit(1)
		}

		// Step 2: Get diff
		diffBody, err := lib.DoGet(ctx, nullifyClient.HttpClient, nullifyClient.BaseURL,
			fmt.Sprintf("%s/%s/autofix/cache/diff%s", basePath, findingID, qs))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting diff: %v\n", err)
			os.Exit(1)
		}

		result := map[string]any{
			"finding_id": findingID,
			"type":       findingType,
			"diff":       json.RawMessage(diffBody),
		}

		// Step 3: Optionally create PR
		if createPR {
			if !quiet {
				fmt.Fprintf(os.Stderr, "Creating PR...\n")
			}
			prBody, err := lib.DoGet(ctx, nullifyClient.HttpClient, nullifyClient.BaseURL,
				fmt.Sprintf("%s/%s/autofix/cache/create_pr%s", basePath, findingID, qs))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating PR: %v\n", err)
				os.Exit(1)
			}
			result["pr"] = json.RawMessage(prBody)
		}

		out, _ := json.MarshalIndent(result, "", "  ")
		_ = output.Print(cmd, out)
	},
}

func init() {
	rootCmd.AddCommand(fixCmd)

	fixCmd.Flags().String("type", "", "Finding type (sast, sca)")
	_ = fixCmd.MarkFlagRequired("type")
	fixCmd.Flags().Bool("create-pr", false, "Create a PR with the fix")
}
