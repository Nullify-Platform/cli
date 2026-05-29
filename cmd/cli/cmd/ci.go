package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/logger"
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
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger(cmd.Context())
		defer logger.Close(ctx)

		ciHost := resolveHost(ctx)
		token, err := lib.GetNullifyToken(ctx, ciHost, nullifyToken, githubToken)
		if err != nil {
			if errors.Is(err, lib.ErrNoToken) {
				fmt.Fprintf(os.Stderr, "Error: not authenticated. Run 'nullify auth login' first.\n")
			} else {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			}
			os.Exit(ExitAuthError)
		}

		nullifyClient := client.NewNullifyClient(ciHost, token)

		creds, err := auth.LoadCredentials()
		queryParams := map[string]string{}
		if err == nil {
			if hostCreds, ok := creds[auth.CredentialKey(ciHost)]; ok && hostCreds.QueryParameters != nil {
				queryParams = hostCreds.QueryParameters
			}
		}

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
			fmt.Fprintf(os.Stderr, "Error: invalid --severity-threshold %q. Valid values: critical, high, medium, low\n", severityThreshold)
			os.Exit(1)
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

		var totalFindings int64
		var apiErrors int64
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

					// limit=1 keeps the payload small; the accurate count
					// comes from the response's "total" field, not the
					// truncated items array.
					count := totalFindingsCount(body)
					if count > 0 {
						atomic.AddInt64(&totalFindings, int64(count))
						mu.Lock()
						fmt.Printf("FAIL: %s has %d %s findings\n", ep.name, count, sev)
						mu.Unlock()
					}
					return nil
				})
			}
		}

		_ = g.Wait()

		// Fail-closed: any scanner request error means we cannot prove the
		// gate is clean, so treat it as a failure rather than passing.
		if apiErrors > 0 {
			fmt.Fprintf(os.Stderr, "Error: %d scanner request(s) failed; failing the gate (cannot confirm a clean result)\n", apiErrors)
			os.Exit(ExitNetworkError)
		}

		if totalFindings > 0 {
			fmt.Printf("\nGate failed: %d findings at or above %s severity\n", totalFindings, severityThreshold)
			os.Exit(ExitFindings)
		}

		fmt.Println("Gate passed: no findings above threshold")
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
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger(cmd.Context())
		defer logger.Close(ctx)

		ciHost := resolveHost(ctx)
		token, err := lib.GetNullifyToken(ctx, ciHost, nullifyToken, githubToken)
		if err != nil {
			if errors.Is(err, lib.ErrNoToken) {
				fmt.Fprintf(os.Stderr, "Error: not authenticated. Run 'nullify auth login' first.\n")
			} else {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			}
			os.Exit(ExitAuthError)
		}

		nullifyClient := client.NewNullifyClient(ciHost, token)

		creds, err := auth.LoadCredentials()
		queryParams := map[string]string{}
		if err == nil {
			if hostCreds, ok := creds[auth.CredentialKey(ciHost)]; ok && hostCreds.QueryParameters != nil {
				queryParams = hostCreds.QueryParameters
			}
		}

		repo, _ := cmd.Flags().GetString("repo")
		if repo == "" {
			repo = lib.DetectRepoFromGit()
		}

		format, _ := cmd.Flags().GetString("format")
		switch format {
		case "markdown", "sarif":
		default:
			fmt.Fprintf(os.Stderr, "Error: invalid --format %q. Valid values: markdown, sarif\n", format)
			os.Exit(1)
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
					atomic.AddInt64(&successCount, 1)

					rows[i*len(severities)+j] = reportRow{
						scanner:  ep.name,
						severity: sev,
						count:    totalFindingsCount(body),
						findings: extractFindings(body),
					}
					return nil
				})
			}
		}

		_ = g.Wait()

		if successCount == 0 {
			fmt.Fprintln(os.Stderr, "Error: all API requests failed, cannot generate report")
			os.Exit(ExitNetworkError)
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
				fmt.Fprintf(os.Stderr, "Error: failed to build SARIF report: %v\n", err)
				os.Exit(ExitNetworkError)
			}
			fmt.Println(string(sarifBytes))
			return
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

// countFindings extracts a count from API response JSON. When used with limit=1,
// it returns 0 or 1 to indicate whether findings exist at a given severity.
func countFindings(body string) int {
	var result any
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return 0
	}

	switch v := result.(type) {
	case []any:
		return len(v)
	case map[string]any:
		if items, ok := v["items"].([]any); ok {
			return len(items)
		}
		if total, ok := v["total"].(float64); ok {
			return int(total)
		}
	}

	return 0
}

// totalFindingsCount extracts an accurate finding count from an API response.
// It prefers the response's "total" field (which reflects the full result set
// regardless of the request's limit) over the length of the truncated items
// array. Falls back to array/items length when no total is present.
func totalFindingsCount(body string) int {
	var result any
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return 0
	}

	switch v := result.(type) {
	case []any:
		return len(v)
	case map[string]any:
		if total, ok := v["total"].(float64); ok {
			return int(total)
		}
		if items, ok := v["items"].([]any); ok {
			return len(items)
		}
		if findings, ok := v["findings"].([]any); ok {
			return len(findings)
		}
	}

	return 0
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
