package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/nullify-platform/cli/internal/logger"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

var securityStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show security posture overview",
	Long:  "Display a summary of your security posture across all scanner types. Quick morning check-in command.",
	Example: `  nullify status
  nullify status -o table`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger(cmd.Context())
		defer logger.L(ctx).Sync()

		statusHost := resolveHost(ctx)
		token, err := lib.GetNullifyToken(ctx, statusHost, nullifyToken, githubToken)
		if err != nil {
			if errors.Is(err, lib.ErrNoToken) {
				fmt.Fprintf(os.Stderr, "Error: not authenticated. Run 'nullify auth login' first.\n")
			} else {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			}
			os.Exit(ExitAuthError)
		}

		nullifyClient := client.NewNullifyClient(statusHost, token)

		creds, err := auth.LoadCredentials()
		queryParams := map[string]string{}
		if err == nil {
			if hostCreds, ok := creds[auth.CredentialKey(statusHost)]; ok && hostCreds.QueryParameters != nil {
				queryParams = hostCreds.QueryParameters
			}
		}

		// Fetch metrics overview
		qs := lib.BuildQueryString(queryParams)
		overviewBody, err := lib.DoPostJSON(ctx, nullifyClient.HttpClient, nullifyClient.BaseURL, "/admin/metrics/overview"+qs, strings.NewReader(`{"query":{}}`))

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching metrics: %v\n", err)
			os.Exit(ExitNetworkError)
		}

		var overview any
		if err := json.Unmarshal([]byte(overviewBody), &overview); err != nil {
			overview = map[string]any{"raw": overviewBody}
		}

		scanners := allScannerEndpoints()

		type scannerResult struct {
			name    string
			summary string
			err     string
		}
		results := make([]scannerResult, len(scanners))
		g, gctx := errgroup.WithContext(ctx)

		for i, scanner := range scanners {
			i, scanner := i, scanner
			g.Go(func() error {
				scannerQS := lib.BuildQueryString(queryParams, "limit", "1")
				body, err := lib.DoGet(gctx, nullifyClient.HttpClient, nullifyClient.BaseURL, scanner.path+scannerQS)
				if err != nil {
					results[i] = scannerResult{name: scanner.name, err: err.Error()}
				} else {
					results[i] = scannerResult{name: scanner.name, summary: summarizeFindingsResponse(body)}
				}
				return nil
			})
		}

		_ = g.Wait()

		statusOutput := securityStatusOutput{
			Overview: overview,
			Scanners: make([]scannerStatusOutput, 0, len(results)),
		}
		for _, result := range results {
			statusOutput.Scanners = append(statusOutput.Scanners, scannerStatusOutput{
				Name:    result.name,
				Summary: result.summary,
				Error:   result.err,
			})
		}

		format, _ := cmd.Flags().GetString("output")
		outputExplicit := cmd.Flags().Lookup("output").Changed

		if format == "table" || !outputExplicit {
			if err := printStatusTable(statusOutput); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return
		}

		out, err := json.Marshal(statusOutput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to encode status output: %v\n", err)
			os.Exit(1)
		}
		if err := output.Print(cmd, out); err != nil {
			fmt.Fprintln(os.Stderr, string(out))
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

type securityStatusOutput struct {
	Overview any                   `json:"overview"`
	Scanners []scannerStatusOutput `json:"scanners"`
}

type scannerStatusOutput struct {
	Name    string `json:"name"`
	Summary string `json:"summary,omitempty"`
	Error   string `json:"error,omitempty"`
}

func printStatusTable(statusOutput securityStatusOutput) error {
	fmt.Println("Security Posture Overview")
	fmt.Println("========================")

	if overviewMap, ok := statusOutput.Overview.(map[string]any); ok {
		overviewWriter := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(overviewWriter, "KEY\tVALUE")

		keys := make([]string, 0, len(overviewMap))
		for key := range overviewMap {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, key := range keys {
			fmt.Fprintf(overviewWriter, "%s\t%s\n", key, statusValueString(overviewMap[key]))
		}
		if err := overviewWriter.Flush(); err != nil {
			return err
		}
	} else {
		pretty, err := json.MarshalIndent(statusOutput.Overview, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(pretty))
	}

	fmt.Println("\nFindings by Scanner")
	fmt.Println("===================")

	scannerWriter := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(scannerWriter, "SCANNER\tSTATUS")
	for _, scanner := range statusOutput.Scanners {
		status := scanner.Summary
		if scanner.Error != "" {
			status = "error: " + scanner.Error
		}
		fmt.Fprintf(scannerWriter, "%s\t%s\n", scanner.Name, status)
	}

	return scannerWriter.Flush()
}

func statusValueString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", value)
		}
		return string(data)
	}
}
