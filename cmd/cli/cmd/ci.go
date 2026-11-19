package cmd

import (
	"fmt"
	"os"
	"slices"
	"strings"

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
so every open one counts at any threshold, and so does a finding whose
severity is UNKNOWN or missing. SAST and CSPM are filtered by severity on
the server, which is also asked for their UNKNOWN findings; a SAST or CSPM
finding with no severity value at all matches no filter and is not seen.
The bughunt list returns closed findings too, so the gate leaves out
bughunt findings that are fixed, allowlisted, archived, false positives or
superseded by a later scan.

` + repositoryScopeHelp + `

Exit codes:
  0 - No findings above threshold
  1 - Findings above threshold found
  2 - Authentication error, including a scanner that refuses access (401 or 403)
  3 - Network/API error, or a response that could not be read
  4 - Invalid flags or flag values`,
	Example: `  # In GitHub Actions, GitLab CI, Bitbucket Pipelines or Azure Pipelines,
  # block on critical or high findings of the repository being built
  nullify ci gate

  # Block only on critical findings
  nullify ci gate --severity-threshold critical

  # Elsewhere, name the repository by its ID at the git provider
  nullify ci gate --repository-id "$(gh api repos/my-org/my-repo --jq .id)"

  # Count the findings of every repository
  nullify ci gate --all-repositories`,
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

The report covers one repository, which it finds as the gate does: see
'nullify ci gate --help'.

A scanner that cannot be read is left out of the report with a warning on
stderr. The report fails only when no scanner can be read.

Exit codes:
  0 - Report written
  2 - Authentication error: every scanner refused access (401 or 403)
  3 - Network/API error: no scanner could be read
  4 - Invalid flags or flag values`,
	Example: `  nullify ci report
  nullify ci report --repository-id 123456789
  nullify ci report --all-repositories
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
	addRepositoryScopeFlags(ciGateCmd)

	ciReportCmd.Flags().String("format", "markdown", "Report format (markdown, sarif)")
	addRepositoryScopeFlags(ciReportCmd)

	ciGateCmd.SetFlagErrorFunc(usageFlagError)
	ciReportCmd.SetFlagErrorFunc(usageFlagError)
}

// repositoryScopeHelp explains how the gate and the report pick their
// repository.
const repositoryScopeHelp = `The gate counts the findings of one repository: the one --repository-id
names, or else the one the CI platform names. That is GITHUB_REPOSITORY_ID
in GitHub Actions, CI_PROJECT_ID in GitLab CI, BITBUCKET_REPO_UUID in
Bitbucket Pipelines, and BUILD_REPOSITORY_ID in Azure Pipelines for an
Azure Repos repository. Elsewhere, such as Jenkins, CircleCI or a laptop,
pass --repository-id, or pass --all-repositories to count every repository
the token can read. With neither, the command exits 4 rather than count
other repositories' findings. Pentest, bughunt and CSPM findings belong to
applications, hosts and cloud accounts rather than repositories, so they
are counted for the whole tenant.`

func addRepositoryScopeFlags(cmd *cobra.Command) {
	cmd.Flags().String("repository-id", "", "Repository ID at the git provider: the GitHub or GitLab numeric ID, the Bitbucket UUID or the Azure Repos GUID (detected in GitHub Actions, GitLab CI, Bitbucket Pipelines and Azure Pipelines)")
	cmd.Flags().Bool("all-repositories", false, "Count the findings of every repository the token can read, instead of one repository")
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
	scope, err := scopeFromFlags(cmd)
	if err != nil {
		return withExitCode(ExitUsageError, err)
	}

	ctx := cmd.Context()
	authCtx, err := resolveCommandAuth(ctx)
	if err != nil {
		return err
	}

	findingType, _ := cmd.Flags().GetString("type")
	fmt.Fprintf(os.Stderr, "Scope: %s\n", scope.describe())

	checks := gateChecks(gateEndpoints(findingType), severitiesAboveThreshold(threshold.String()))
	results := runGateChecks(ctx, clientGetter(authCtx.Client()), authCtx.QueryParams, checks, threshold, scope)
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
	scope, err := scopeFromFlags(cmd)
	if err != nil {
		return withExitCode(ExitUsageError, err)
	}

	ctx := cmd.Context()
	authCtx, err := resolveCommandAuth(ctx)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Scope: %s\n", scope.describe())
	reports := collectScannerReports(
		ctx, clientGetter(authCtx.Client()), authCtx.QueryParams,
		allScannerEndpoints(), scope,
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
// requests and attribute the same findings to every severity. An endpoint
// that filters by severity is also asked for its UNKNOWN findings, which
// count at every threshold and no threshold name would return.
func scannerSeverities(ep scannerEndpoint, severities []string) []string {
	if !ep.supportsSeverity {
		return []string{""}
	}
	return append(slices.Clone(severities), severityUnknown.String())
}

// scannerQueryParams returns the filters for one scanner list request. The
// page size and cursor are added per page by visitFindingPages.
func scannerQueryParams(ep scannerEndpoint, severity string, scope repositoryScope) []string {
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
	return append(params, scope.queryParams(ep)...)
}

// scannerLabel names a scanner/severity pair in diagnostic output. A scanner
// queried without a severity filter is named alone.
func scannerLabel(ep scannerEndpoint, severity string) string {
	if severity == "" {
		return ep.name
	}
	return fmt.Sprintf("%s (%s)", ep.name, severity)
}
