package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/spf13/cobra"
)

var securityStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show security posture overview",
	Long:  "Display a summary of your security posture across all scanner types. Quick morning check-in command.",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger()
		defer logger.L(ctx).Sync()

		statusHost := resolveHost(ctx)
		token, err := lib.GetNullifyToken(ctx, statusHost, nullifyToken, githubToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: not authenticated. Run 'nullify auth login' first.\n")
			os.Exit(1)
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
		qs := buildFindingsQueryString(queryParams)
		overviewBody, err := doStatusGet(nullifyClient, "/admin/metrics/overview"+qs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching metrics: %v\n", err)
			os.Exit(1)
		}

		// Try to pretty-print
		var overview interface{}
		if err := json.Unmarshal([]byte(overviewBody), &overview); err == nil {
			pretty, _ := json.MarshalIndent(overview, "", "  ")
			fmt.Println("Security Posture Overview")
			fmt.Println("========================")
			fmt.Println(string(pretty))
		} else {
			fmt.Println(overviewBody)
		}

		// Fetch individual scanner postures
		scanners := []struct {
			name string
			path string
		}{
			{"SAST", "/sast/findings"},
			{"SCA Dependencies", "/sca/dependencies/findings"},
			{"SCA Containers", "/sca/containers/findings"},
			{"Secrets", "/secrets/findings"},
			{"Pentest", "/dast/pentest/findings"},
			{"BugHunt", "/dast/bughunt/findings"},
			{"CSPM", "/cspm/findings"},
		}

		fmt.Println("\nFindings by Scanner")
		fmt.Println("===================")
		fmt.Printf("%-20s %s\n", "Scanner", "Status")
		fmt.Printf("%-20s %s\n", "-------", "------")

		for _, scanner := range scanners {
			body, err := doStatusGet(nullifyClient, scanner.path+qs+"&limit=1")
			if err != nil {
				fmt.Printf("%-20s error: %v\n", scanner.name, err)
				continue
			}

			// Try to extract count information
			var result interface{}
			if err := json.Unmarshal([]byte(body), &result); err == nil {
				switch v := result.(type) {
				case []interface{}:
					fmt.Printf("%-20s %d findings returned\n", scanner.name, len(v))
				case map[string]interface{}:
					if items, ok := v["items"].([]interface{}); ok {
						fmt.Printf("%-20s %d findings returned\n", scanner.name, len(items))
					} else if total, ok := v["total"].(float64); ok {
						fmt.Printf("%-20s %.0f total findings\n", scanner.name, total)
					} else {
						fmt.Printf("%-20s data available\n", scanner.name)
					}
				default:
					fmt.Printf("%-20s data available\n", scanner.name)
				}
			} else {
				fmt.Printf("%-20s data available\n", scanner.name)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(securityStatusCmd)
}

func doStatusGet(c *client.NullifyClient, path string) (string, error) {
	req, err := http.NewRequest("GET", c.BaseURL+path, nil)
	if err != nil {
		return "", err
	}

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("API returned %d", resp.StatusCode)
	}

	return string(body), nil
}
