package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/nullify-platform/cli/internal/findings"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
)

var fixCmd = &cobra.Command{
	Use:   "fix <finding-id>",
	Short: "Generate an autofix for a finding",
	Long: `Generate an automated fix for a security finding and wait for it to finish.

The fix run opens any pull request itself. --create-pr waits for that pull
request and reports it.`,
	Example: `  # Fix a SAST finding
  nullify fix abc123 --type sast

  # Fix and report the pull request
  nullify fix abc123 --type sast --create-pr

  # Fix an SCA dependency finding
  nullify fix def456 --type sca`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		findingID := args[0]
		findingType, _ := cmd.Flags().GetString("type")
		createPR, _ := cmd.Flags().GetBool("create-pr")

		authCtx, err := resolveCommandAuth(cmd.Context())
		if err != nil {
			return err
		}

		if !quiet {
			fmt.Fprintf(os.Stderr, "Generating fix for %s finding %s...\n", findingType, findingID)
		}
		fixResult, err := findings.Fix(cmd.Context(), authCtx.APIClient(), findingType, findingID, createPR)
		if err != nil {
			return findingsError(err)
		}

		result := map[string]any{
			"finding_id": findingID,
			"type":       findingType,
		}
		if fixResult.StillRunning {
			result["still_running"] = true
		}
		if len(fixResult.Diff) > 0 {
			result["diff"] = fixResult.Diff
		}
		if fixResult.PullRequest != nil {
			result["pr"] = fixResult.PullRequest
		}

		out, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		if err := output.Print(cmd, out); err != nil {
			fmt.Fprintln(os.Stderr, string(out))
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(fixCmd)

	autofixTypes := findings.NamesWith(func(t findings.Type) bool { return t.AutofixFix != nil })
	fixCmd.Flags().String("type", "", "Finding type (sca, "+strings.Join(autofixTypes, ", ")+")")
	_ = fixCmd.MarkFlagRequired("type")
	fixCmd.Flags().Bool("create-pr", false, "Wait for and report the pull request")
}
