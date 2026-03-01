package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/logger/pkg/logger"
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
  1 - Findings above threshold found (or error)`,
	Example: `  # Block on critical or high findings
  nullify ci gate

  # Block only on critical findings
  nullify ci gate --severity-threshold critical

  # Check a specific repo
  nullify ci gate --repo my-org/my-repo`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger()
		defer logger.L(ctx).Sync()

		ciHost := resolveHost(ctx)
		token, err := lib.GetNullifyToken(ctx, ciHost, nullifyToken, githubToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: not authenticated\n")
			os.Exit(1)
		}

		nullifyClient := client.NewNullifyClient(ciHost, token)

		creds, err := auth.LoadCredentials()
		queryParams := map[string]string{}
		if err == nil {
			if hostCreds, ok := creds[ciHost]; ok && hostCreds.QueryParameters != nil {
				queryParams = hostCreds.QueryParameters
			}
		}

		severityThreshold, _ := cmd.Flags().GetString("severity-threshold")
		findingType, _ := cmd.Flags().GetString("type")
		repo, _ := cmd.Flags().GetString("repo")

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
		totalRequests := int64(len(endpoints) * len(severities))
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

					count := countFindings(body)
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

		if apiErrors > 0 && apiErrors == totalRequests {
			fmt.Fprintf(os.Stderr, "Error: all API requests failed, cannot determine gate status\n")
			os.Exit(1)
		}

		if totalFindings > 0 {
			fmt.Printf("\nGate failed: %d findings at or above %s severity\n", totalFindings, severityThreshold)
			os.Exit(1)
		}

		fmt.Println("Gate passed: no findings above threshold")
	},
}

var ciReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a markdown summary for PR comments",
	Long: "Output a markdown summary of security findings suitable for PR comments. Shows counts by type and severity.",
	Example: `  nullify ci report
  nullify ci report --repo my-org/my-repo`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger()
		defer logger.L(ctx).Sync()

		ciHost := resolveHost(ctx)
		token, err := lib.GetNullifyToken(ctx, ciHost, nullifyToken, githubToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: not authenticated\n")
			os.Exit(1)
		}

		nullifyClient := client.NewNullifyClient(ciHost, token)

		creds, err := auth.LoadCredentials()
		queryParams := map[string]string{}
		if err == nil {
			if hostCreds, ok := creds[ciHost]; ok && hostCreds.QueryParameters != nil {
				queryParams = hostCreds.QueryParameters
			}
		}

		repo, _ := cmd.Flags().GetString("repo")
		if repo == "" {
			repo = lib.DetectRepoFromGit()
		}

		endpoints := allScannerEndpoints()
		severities := []string{"critical", "high", "medium", "low"}

		type reportRow struct {
			scanner  string
			severity string
			count    int
		}

		rows := make([]reportRow, len(endpoints)*len(severities))
		g, gctx := errgroup.WithContext(ctx)

		for i, ep := range endpoints {
			for j, sev := range severities {
				i, j, ep, sev := i, j, ep, sev
				g.Go(func() error {
					// limit=1 is used to check existence, not count exact totals
					params := []string{"severity", sev, "status", "open", "limit", "1"}
					if repo != "" {
						params = append(params, "repository", repo)
					}
					qs := lib.BuildQueryString(queryParams, params...)

					body, err := lib.DoGet(gctx, nullifyClient.HttpClient, nullifyClient.BaseURL, ep.path+qs)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to query %s (%s): %v\n", ep.name, sev, err)
						return nil
					}

					rows[i*len(severities)+j] = reportRow{
						scanner:  ep.name,
						severity: sev,
						count:    countFindings(body),
					}
					return nil
				})
			}
		}

		_ = g.Wait()

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
