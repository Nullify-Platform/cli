package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/logger"
	"github.com/nullify-platform/cli/internal/output"
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
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := setupLogger(cmd.Context())
		defer logger.Close(ctx)

		findingID := args[0]

		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			return err
		}
		nullifyClient := authCtx.Client()
		queryParams := authCtx.QueryParams

		findingType, _ := cmd.Flags().GetString("type")
		createPR, _ := cmd.Flags().GetBool("create-pr")

		var basePath string
		switch findingType {
		case "sast":
			basePath = "/sast/findings"
		case "sca":
			basePath = "/sca/dependencies/findings"
		default:
			return fmt.Errorf("--type must be 'sast' or 'sca'")
		}

		qs := lib.BuildQueryString(queryParams)

		// Step 1: Generate autofix
		if !quiet {
			fmt.Fprintf(os.Stderr, "Generating fix for %s finding %s...\n", findingType, findingID)
		}
		_, err = lib.DoPost(ctx, nullifyClient.HttpClient, nullifyClient.BaseURL,
			fmt.Sprintf("%s/%s/autofix/fix%s", basePath, url.PathEscape(findingID), qs))
		if err != nil {
			return fmt.Errorf("generating fix: %w", err)
		}

		// Step 2: Get diff
		diffBody, err := lib.DoGet(ctx, nullifyClient.HttpClient, nullifyClient.BaseURL,
			fmt.Sprintf("%s/%s/autofix/cache/diff%s", basePath, url.PathEscape(findingID), qs))
		if err != nil {
			return fmt.Errorf("getting diff: %w", err)
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
			prBody, err := lib.DoPost(ctx, nullifyClient.HttpClient, nullifyClient.BaseURL,
				fmt.Sprintf("%s/%s/autofix/cache/create_pr%s", basePath, url.PathEscape(findingID), qs))
			if err != nil {
				return fmt.Errorf("creating PR: %w", err)
			}
			result["pr"] = json.RawMessage(prBody)
		}

		out, _ := json.MarshalIndent(result, "", "  ")
		if err := output.Print(cmd, out); err != nil {
			fmt.Fprintln(os.Stderr, string(out))
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(fixCmd)

	fixCmd.Flags().String("type", "", "Finding type (sast, sca)")
	_ = fixCmd.MarkFlagRequired("type")
	fixCmd.Flags().Bool("create-pr", false, "Create a PR with the fix")
}
