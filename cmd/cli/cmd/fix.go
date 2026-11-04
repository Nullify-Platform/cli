package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/findings"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
)

var fixCmd = &cobra.Command{
	Use:   "fix <finding-id>",
	Short: "Generate an autofix for a finding",
	Long: `Generate an automated fix for a security finding and wait for it to finish.

The fix run opens any pull request itself. --create-pr waits for a pull request
that this run opened and reports it.

The command exits non-zero when the fix failed, when it is still running at
--timeout, or when --create-pr finds no new pull request. A run that is still
running continues on the server. --no-wait starts the run, prints its state and
exits 0. Check a run with nullify findings fix-status.`,
	Example: `  # Fix a SAST finding
  nullify fix abc123 --type sast

  # Fix and report the pull request
  nullify fix abc123 --type sast --create-pr

  # Fix an SCA dependency finding
  nullify fix def456 --type sca

  # Start the run and continue at once
  nullify fix abc123 --type sast --no-wait
  nullify findings fix-status abc123 --type sast`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		findingID := args[0]
		findingType, _ := cmd.Flags().GetString("type")
		createPR, _ := cmd.Flags().GetBool("create-pr")
		noWait, _ := cmd.Flags().GetBool("no-wait")
		timeout, _ := cmd.Flags().GetDuration("timeout")

		authCtx, err := resolveCommandAuth(cmd.Context())
		if err != nil {
			return err
		}

		if !quiet {
			fmt.Fprintf(os.Stderr, "Generating fix for %s finding %s...\n", findingType, findingID)
		}
		apiClient, err := newRefreshingAPIClient(cmd.Context(), authCtx, authCtx.QueryParams)
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}
		return runFix(cmd, apiClient, findingID, findingType, noWait, findings.FixOptions{WaitForPR: createPR, Timeout: timeout})
	},
}

func runFix(cmd *cobra.Command, c *api.Client, findingID, findingType string, noWait bool, opts findings.FixOptions) error {
	if noWait {
		start, err := findings.StartFix(cmd.Context(), c, findingType, findingID)
		if err != nil {
			return findingsError(err)
		}
		return reportFix(cmd, findingID, findingType, findings.FixResult{State: start.State, RunID: start.RunID})
	}

	fixResult, err := findings.Fix(cmd.Context(), c, findingType, findingID, opts)
	if err != nil {
		if fixResult.CheckWith != "" {
			_ = reportFix(cmd, findingID, findingType, fixResult)
		}
		return findingsError(err)
	}
	return reportFix(cmd, findingID, findingType, fixResult)
}

// reportFix prints the outcome and returns the failure of the run, so that a fix
// that did not deliver its result exits non-zero after it prints what it has.
func reportFix(cmd *cobra.Command, findingID, findingType string, fixResult findings.FixResult) error {
	result := map[string]any{
		"finding_id": findingID,
		"type":       findingType,
		"state":      fixResult.State,
	}
	if fixResult.RunID != "" {
		result["run_id"] = fixResult.RunID
	}
	if fixResult.CheckWith != "" {
		result["check_with"] = fixResult.CheckWith
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
	return fixResult.Failure
}

func init() {
	rootCmd.AddCommand(fixCmd)

	autofixTypes := findings.NamesWith(func(t findings.Type) bool { return t.AutofixFix != nil })
	fixCmd.Flags().String("type", "", "Finding type (sca, "+strings.Join(autofixTypes, ", ")+")")
	_ = fixCmd.MarkFlagRequired("type")
	fixCmd.Flags().Bool("create-pr", false, "Wait for and report a pull request that this run opens")
	fixCmd.Flags().Bool("no-wait", false, "Start the run, print its state and exit 0")
	fixCmd.Flags().Duration("timeout", findings.DefaultFixTimeout, "How long to wait for the run")
	fixCmd.MarkFlagsMutuallyExclusive("no-wait", "create-pr")
	fixCmd.MarkFlagsMutuallyExclusive("no-wait", "timeout")
}
