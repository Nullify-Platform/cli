package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

var securityStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show security posture overview",
	Long: "Display a summary of your security posture across all scanner types. Quick morning check-in command.",
	Example: `  nullify status
  nullify status -o table`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger()
		defer logger.L(ctx).Sync()

		statusHost := resolveHost(ctx)
		token, err := lib.GetNullifyToken(ctx, statusHost, nullifyToken, githubToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: not authenticated. Run 'nullify auth login' first.\n")
			os.Exit(ExitAuthError)
		}

		nullifyClient := client.NewNullifyClient(statusHost, token)

		creds, err := auth.LoadCredentials()
		queryParams := map[string]string{}
		if err == nil {
			if hostCreds, ok := creds[statusHost]; ok && hostCreds.QueryParameters != nil {
				queryParams = hostCreds.QueryParameters
			}
		}

		// Fetch metrics overview
		qs := lib.BuildQueryString(queryParams)
		overviewBody, err := lib.DoGet(ctx, nullifyClient.HttpClient, nullifyClient.BaseURL, "/admin/metrics/overview"+qs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching metrics: %v\n", err)
			os.Exit(ExitNetworkError)
		}

		// Try to pretty-print
		var overview any
		if err := json.Unmarshal([]byte(overviewBody), &overview); err == nil {
			pretty, _ := json.MarshalIndent(overview, "", "  ")
			fmt.Println("Security Posture Overview")
			fmt.Println("========================")
			fmt.Println(string(pretty))
		} else {
			fmt.Println(overviewBody)
		}

		// Fetch individual scanner postures
		scanners := allScannerEndpoints()

		fmt.Println("\nFindings by Scanner")
		fmt.Println("===================")
		fmt.Printf("%-20s %s\n", "Scanner", "Status")
		fmt.Printf("%-20s %s\n", "-------", "------")

		type scannerResult struct {
			name    string
			summary string
		}
		results := make([]scannerResult, len(scanners))
		g, gctx := errgroup.WithContext(ctx)

		for i, scanner := range scanners {
			i, scanner := i, scanner
			g.Go(func() error {
				scannerQS := lib.BuildQueryString(queryParams, "limit", "1")
				body, err := lib.DoGet(gctx, nullifyClient.HttpClient, nullifyClient.BaseURL, scanner.path+scannerQS)
				if err != nil {
					results[i] = scannerResult{name: scanner.name, summary: fmt.Sprintf("error: %v", err)}
				} else {
					results[i] = scannerResult{name: scanner.name, summary: summarizeFindingsResponse(body)}
				}
				return nil
			})
		}

		_ = g.Wait()

		for _, r := range results {
			fmt.Printf("%-20s %s\n", r.name, r.summary)
		}
	},
}

func init() {
	rootCmd.AddCommand(securityStatusCmd)
}

// summarizeFindingsResponse extracts a human-readable summary from a findings API response.
func summarizeFindingsResponse(body string) string {
	var result any
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return "data available"
	}

	switch v := result.(type) {
	case []any:
		if len(v) == 1 {
			return "1 finding returned"
		}
		return fmt.Sprintf("%d findings returned", len(v))
	case map[string]any:
		if items, ok := v["items"].([]any); ok {
			if len(items) == 1 {
				return "1 finding returned"
			}
			return fmt.Sprintf("%d findings returned", len(items))
		}
		if total, ok := v["total"].(float64); ok {
			if total == 1 {
				return "1 total finding"
			}
			return fmt.Sprintf("%.0f total findings", total)
		}
	}

	return "data available"
}
