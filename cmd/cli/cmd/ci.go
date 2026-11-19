package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/nullify-platform/cli/internal/lib"
	"github.com/spf13/cobra"
)

var ciCmd = &cobra.Command{
	Use:   "ci",
	Short: "CI/CD integration commands",
	Long:  "Commands for integrating Nullify into CI/CD pipelines.",
}

var ciGateCmd = &cobra.Command{
	Use:   "gate",
	Short: "Quality gate - exit non-zero if findings exceed threshold",
	Long: `Check if security findings exceed the severity threshold and exit non-zero if they do.
Use this in CI/CD pipelines to block deployments with critical/high findings.

The threshold applies to every scanner. A finding counts when its own
severity is at or above the threshold. Secrets findings carry no severity,
and neither does a finding whose severity is missing or unknown, so every
open one counts at any threshold. The bughunt list returns closed findings
too, so the gate leaves out bughunt findings that are fixed, allowlisted,
archived, false positives or superseded by a later scan.

Exit codes:
  0 - No findings above threshold
  1 - Findings above threshold found
  2 - Authentication error, including a scanner that refuses access (401 or 403)
  3 - Network/API error, or a response that could not be read
  4 - Invalid flags or flag values`,
	Example: `  # Block on critical or high findings
  nullify ci gate

  # Block only on critical findings
  nullify ci gate --severity-threshold critical

  # Check a specific repo
  nullify ci gate --repo my-org/my-repo`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCIGate(cmd)
	},
}

var ciReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a findings report (markdown or SARIF)",
	Long: `Output a report of security findings. The default markdown format produces a
summary table suitable for PR comments (counts by type and severity). The sarif
format emits a SARIF v2.1.0 document for upload to code-scanning tools.

Each finding is counted once, under its own severity. Findings without a
severity, which includes every secrets finding, are counted as unknown.
Closed bughunt findings are left out, as the gate leaves them out.

A scanner that cannot be read is left out of the report with a warning on
stderr. The report fails only when no scanner can be read.

Exit codes:
  0 - Report written
  2 - Authentication error: every scanner refused access (401 or 403)
  3 - Network/API error: no scanner could be read
  4 - Invalid flags or flag values`,
	Example: `  nullify ci report
  nullify ci report --repo my-org/my-repo
  nullify ci report --format sarif > nullify.sarif`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCIReport(cmd)
	},
}

func init() {
	rootCmd.AddCommand(ciCmd)
	ciCmd.AddCommand(ciGateCmd)
	ciCmd.AddCommand(ciReportCmd)

	ciGateCmd.Flags().String("severity-threshold", "high", "Minimum severity to fail on (critical, high, medium, low)")
	ciGateCmd.Flags().String("type", "", "Filter by finding type (sast, sca_dependencies, sca_containers, secrets, pentest, bughunt, cspm)")
	ciGateCmd.Flags().String("repo", "", "Repository name (auto-detected from git if not set)")

	ciReportCmd.Flags().String("repo", "", "Repository name (auto-detected from git if not set)")
	ciReportCmd.Flags().String("format", "markdown", "Report format (markdown, sarif)")

	ciGateCmd.SetFlagErrorFunc(usageFlagError)
	ciReportCmd.SetFlagErrorFunc(usageFlagError)
}

// usageFlagError gives a flag the command cannot parse the usage exit code.
func usageFlagError(_ *cobra.Command, err error) error {
	return withExitCode(ExitUsageError, err)
}

func runCIGate(cmd *cobra.Command) error {
	thresholdName, _ := cmd.Flags().GetString("severity-threshold")
	threshold, err := parseSeverityThreshold(thresholdName)
	if err != nil {
		return withExitCode(ExitUsageError, err)
	}

	ctx := cmd.Context()
	authCtx, err := resolveCommandAuth(ctx)
	if err != nil {
		return err
	}

	findingType, _ := cmd.Flags().GetString("type")
	repo := ciRepositoryName(cmd)

	checks := gateChecks(gateEndpoints(findingType), severitiesAboveThreshold(threshold.String()))
	results := runGateChecks(ctx, clientGetter(authCtx.Client()), authCtx.QueryParams, checks, threshold, repo)
	if err := gateVerdict(results, threshold); err != nil {
		if ExitCodeForError(err) == ExitFindings {
			// The FAIL lines and the summary already explain the result.
			cmd.SilenceErrors = true
		}
		return err
	}

	fmt.Println("Gate passed: no findings above threshold")
	return nil
}

func runCIReport(cmd *cobra.Command) error {
	format, _ := cmd.Flags().GetString("format")
	switch format {
	case "markdown", "sarif":
	default:
		return usageError("invalid --format %q. Valid values: markdown, sarif", format)
	}

	ctx := cmd.Context()
	authCtx, err := resolveCommandAuth(ctx)
	if err != nil {
		return err
	}

	reports := collectScannerReports(
		ctx, clientGetter(authCtx.Client()), authCtx.QueryParams,
		allScannerEndpoints(), ciRepositoryName(cmd),
	)
	if err := checkReportReads(reports); err != nil {
		return err
	}

	if format == "sarif" {
		return printSARIFReport(reports)
	}
	printMarkdownReport(reportRows(reports))
	return nil
}

// ciRepositoryName returns the --repo flag, or the repository of the working
// directory when the flag is not set.
func ciRepositoryName(cmd *cobra.Command) string {
	repo, _ := cmd.Flags().GetString("repo")
	if repo == "" {
		return lib.DetectRepoFromGit()
	}
	return repo
}

// gateEndpoints returns the scanners the gate checks: the --type scanner, or
// every scanner when the type is empty or unknown.
func gateEndpoints(findingType string) []scannerEndpoint {
	endpoints := allScannerEndpoints()
	if findingType == "" {
		return endpoints
	}
	if filtered := filterEndpointsByType(endpoints, findingType); filtered != nil {
		return filtered
	}
	fmt.Fprintf(os.Stderr, "Warning: unknown finding type %q, scanning all types\n", findingType)
	return endpoints
}

func severitiesAboveThreshold(threshold string) []string {
	for i, s := range thresholdNames {
		if s == threshold {
			return thresholdNames[:i+1]
		}
	}
	return []string{"critical", "high"}
}

// scannerSeverities returns the severity values to query an endpoint with. An
// endpoint with no server-side severity filter is queried once with an empty
// severity: fanning out over the threshold list there would issue identical
// requests and attribute the same findings to every severity.
func scannerSeverities(ep scannerEndpoint, severities []string) []string {
	if !ep.supportsSeverity {
		return []string{""}
	}
	return severities
}

// scannerQueryParams returns the filters for one scanner list request. The
// page size and cursor are added per page by visitFindingPages.
func scannerQueryParams(ep scannerEndpoint, severity, repo string) []string {
	params := []string{}
	if ep.supportsSeverity && severity != "" {
		params = append(params, "severity", strings.ToUpper(severity))
	}
	if ep.supportsOpenStatus {
		params = append(params, "status", "open")
	}
	if ep.supportsIsResolved {
		params = append(params, "isResolved", "false")
	}
	if repo != "" {
		params = append(params, "repository", repo)
	}
	return params
}

// scannerLabel names a scanner/severity pair in diagnostic output. A scanner
// queried without a severity filter is named alone.
func scannerLabel(ep scannerEndpoint, severity string) string {
	if severity == "" {
		return ep.name
	}
	return fmt.Sprintf("%s (%s)", ep.name, severity)
}
