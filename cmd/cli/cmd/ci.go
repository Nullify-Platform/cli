package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
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

Exit codes:
  0 - No findings above threshold
  1 - Findings above threshold found
  2 - Authentication error
  3 - Network/API error`,
	Example: `  # Block on critical or high findings
  nullify ci gate

  # Block only on critical findings
  nullify ci gate --severity-threshold critical

  # Check a specific repo
  nullify ci gate --repo my-org/my-repo`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			return err
		}
		nullifyClient := authCtx.Client()
		queryParams := authCtx.QueryParams

		severityThreshold, _ := cmd.Flags().GetString("severity-threshold")
		findingType, _ := cmd.Flags().GetString("type")
		repo, _ := cmd.Flags().GetString("repo")

		validSeverities := []string{"critical", "high", "medium", "low"}
		validThreshold := false
		for _, s := range validSeverities {
			if s == severityThreshold {
				validThreshold = true
				break
			}
		}
		if !validThreshold {
			err := fmt.Errorf("invalid --severity-threshold %q. Valid values: critical, high, medium, low", severityThreshold)
			return withExitCode(1, err)
		}

		if repo == "" {
			repo = lib.DetectRepoFromGit()
		}

		severities := severitiesAboveThreshold(severityThreshold)

		endpoints := allScannerEndpoints()
		if findingType != "" {
			if filtered := filterEndpointsByType(endpoints, findingType); filtered != nil {
				endpoints = filtered
			} else {
				fmt.Fprintf(os.Stderr, "Warning: unknown finding type %q, scanning all types\n", findingType)
			}
		}

		var findingsFound int64
		var apiErrors int64
		var unreadable int64
		var mu sync.Mutex
		g, gctx := errgroup.WithContext(ctx)

		for _, ep := range endpoints {
			for _, sev := range severities {
				ep, sev := ep, sev
				g.Go(func() error {
					params := []string{"severity", sev, "status", "open", "limit", "1"}
					if repo != "" {
						params = append(params, "repository", repo)
					}
					qs := lib.BuildQueryString(queryParams, params...)

					body, err := lib.DoGet(gctx, nullifyClient.HttpClient, nullifyClient.BaseURL, ep.path+qs)
					if err != nil {
						mu.Lock()
						fmt.Fprintf(os.Stderr, "Warning: failed to query %s (%s): %v\n", ep.name, sev, err)
						mu.Unlock()
						atomic.AddInt64(&apiErrors, 1)
						return nil
					}

					count, err := countFindings(body)
					if err != nil {
						mu.Lock()
						fmt.Fprintf(os.Stderr, "Error: unreadable response from %s (%s): %v\n", ep.name, sev, err)
						mu.Unlock()
						atomic.AddInt64(&unreadable, 1)
						return nil
					}

					if count > 0 {
						atomic.AddInt64(&findingsFound, 1)
						mu.Lock()
						fmt.Printf("FAIL: %s has open %s findings\n", ep.name, sev)
						mu.Unlock()
					}
					return nil
				})
			}
		}

		_ = g.Wait()

		if apiErrors > 0 {
			err := fmt.Errorf("%d scanner request(s) failed; failing the gate (cannot confirm a clean result)", apiErrors)
			return withExitCode(ExitNetworkError, err)
		}

		if unreadable > 0 {
			err := fmt.Errorf("%d scanner response(s) could not be read; failing the gate (cannot confirm a clean result)", unreadable)
			return withExitCode(ExitNetworkError, err)
		}

		if findingsFound > 0 {
			fmt.Printf("\nGate failed: open findings at or above %s severity\n", severityThreshold)
			cmd.SilenceErrors = true
			return withExitCode(ExitFindings, fmt.Errorf("gate failed: open findings at or above %s severity", severityThreshold))
		}

		fmt.Println("Gate passed: no findings above threshold")
		return nil
	},
}

var ciReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a findings report (markdown or SARIF)",
	Long: `Output a report of security findings. The default markdown format produces a
summary table suitable for PR comments (counts by type and severity). The sarif
format emits a SARIF v2.1.0 document for upload to code-scanning tools.`,
	Example: `  nullify ci report
  nullify ci report --repo my-org/my-repo
  nullify ci report --format sarif > nullify.sarif`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			return err
		}
		nullifyClient := authCtx.Client()
		queryParams := authCtx.QueryParams

		repo, _ := cmd.Flags().GetString("repo")
		if repo == "" {
			repo = lib.DetectRepoFromGit()
		}

		format, _ := cmd.Flags().GetString("format")
		switch format {
		case "markdown", "sarif":
		default:
			return withExitCode(1, fmt.Errorf("invalid --format %q. Valid values: markdown, sarif", format))
		}

		endpoints := allScannerEndpoints()
		severities := []string{"critical", "high", "medium", "low"}

		type reportRow struct {
			scanner  string
			severity string
			count    int
			findings []json.RawMessage
		}

		rows := make([]reportRow, len(endpoints)*len(severities))
		g, gctx := errgroup.WithContext(ctx)
		var successCount int64
		var apiErrors int64
		var mu sync.Mutex

		for i, ep := range endpoints {
			for j, sev := range severities {
				i, j, ep, sev := i, j, ep, sev
				g.Go(func() error {
					params := []string{"severity", sev, "status", "open", "limit", "1000"}
					if repo != "" {
						params = append(params, "repository", repo)
					}
					qs := lib.BuildQueryString(queryParams, params...)

					body, err := lib.DoGet(gctx, nullifyClient.HttpClient, nullifyClient.BaseURL, ep.path+qs)
					if err != nil {
						atomic.AddInt64(&apiErrors, 1)
						mu.Lock()
						fmt.Fprintf(os.Stderr, "Warning: failed to query %s (%s): %v\n", ep.name, sev, err)
						mu.Unlock()
						return nil
					}
					count, err := countFindings(body)
					if err != nil {
						atomic.AddInt64(&apiErrors, 1)
						mu.Lock()
						fmt.Fprintf(os.Stderr, "Warning: unreadable response from %s (%s): %v\n", ep.name, sev, err)
						mu.Unlock()
						return nil
					}
					atomic.AddInt64(&successCount, 1)

					rows[i*len(severities)+j] = reportRow{
						scanner:  ep.name,
						severity: sev,
						count:    count,
						findings: extractFindings(body),
					}
					return nil
				})
			}
		}

		_ = g.Wait()

		if successCount == 0 {
			return networkError("all API requests failed, cannot generate report")
		}
		if apiErrors > 0 {
			fmt.Fprintf(os.Stderr, "Warning: %d API requests failed while generating the report\n", apiErrors)
		}

		if format == "sarif" {
			all := make([]json.RawMessage, 0)
			for _, row := range rows {
				all = append(all, row.findings...)
			}
			wrapped, _ := json.Marshal(map[string]any{"findings": all, "total": len(all)})
			sarifBytes, err := output.SARIFBytes(wrapped)
			if err != nil {
				return networkError("failed to build SARIF report: %w", err)
			}
			fmt.Println(string(sarifBytes))
			return nil
		}

		fmt.Println("## Nullify Security Report")
		fmt.Println()
		fmt.Println("| Scanner | Severity | Count |")
		fmt.Println("|---------|----------|-------|")

		for _, row := range rows {
			if row.count > 0 {
				fmt.Printf("| %s | %s | %d |\n", row.scanner, row.severity, row.count)
			}
		}

		fmt.Println()
		fmt.Println("*Generated by [Nullify CLI](https://github.com/nullify-platform/cli)*")
		return nil
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
}

func severitiesAboveThreshold(threshold string) []string {
	all := []string{"critical", "high", "medium", "low"}
	for i, s := range all {
		if s == threshold {
			return all[:i+1]
		}
	}
	return []string{"critical", "high"}
}

// errUnreadableFindings reports a findings response that does not carry the
// scanner envelope. It is never reported as a count of zero: a gate that cannot
// read the response must block the build rather than declare the repo clean.
var errUnreadableFindings = errors.New("unrecognised findings response envelope")

// countFindings returns the number of findings in a scanner API response. Every
// endpoint in allScannerEndpoints returns {"findings":[...],"numItems":N,
// "nextToken":"..."}, except /dast/bughunt/findings which omits numItems. The
// count is page-scoped and therefore bounded by the request's limit; the API
// exposes no grand total.
func countFindings(body string) (int, error) {
	var envelope struct {
		Findings json.RawMessage `json:"findings"`
		NumItems *int            `json:"numItems"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return 0, fmt.Errorf("%w: %w", errUnreadableFindings, err)
	}
	if len(envelope.Findings) == 0 {
		return 0, fmt.Errorf("%w: no \"findings\" field", errUnreadableFindings)
	}

	if envelope.NumItems != nil {
		return *envelope.NumItems, nil
	}

	var findings []json.RawMessage
	if err := json.Unmarshal(envelope.Findings, &findings); err != nil {
		return 0, fmt.Errorf("%w: \"findings\" is not an array: %w", errUnreadableFindings, err)
	}
	return len(findings), nil
}

// extractFindings pulls the finding objects out of an API response body so they
// can be rendered (e.g. as SARIF). It understands a top-level array as well as
// the common {findings:[...]} and {items:[...]} envelopes.
func extractFindings(body string) []json.RawMessage {
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(body), &arr); err == nil {
		return arr
	}

	var obj struct {
		Findings []json.RawMessage `json:"findings"`
		Items    []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &obj); err == nil {
		if obj.Findings != nil {
			return obj.Findings
		}
		if obj.Items != nil {
			return obj.Items
		}
	}

	return nil
}
