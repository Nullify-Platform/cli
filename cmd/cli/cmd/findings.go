package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/spf13/cobra"
)

var findingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "List security findings across all scanner types",
	Long: `Query and display security findings from all Nullify scanners.
Supports SAST, SCA (dependencies and containers), Secrets, Pentest, BugHunt, and CSPM.
Auto-detects the current repository from git if --repo is not specified.`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger()
		defer logger.L(ctx).Sync()

		findingsHost := resolveHost(ctx)
		token, err := lib.GetNullifyToken(ctx, findingsHost, nullifyToken, githubToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: not authenticated. Run 'nullify auth login' first.\n")
			os.Exit(1)
		}

		nullifyClient := client.NewNullifyClient(findingsHost, token)

		creds, err := auth.LoadCredentials()
		queryParams := map[string]string{}
		if err == nil {
			if hostCreds, ok := creds[findingsHost]; ok && hostCreds.QueryParameters != nil {
				queryParams = hostCreds.QueryParameters
			}
		}

		severity, _ := cmd.Flags().GetString("severity")
		status, _ := cmd.Flags().GetString("status")
		findingType, _ := cmd.Flags().GetString("type")
		repo, _ := cmd.Flags().GetString("repo")
		limit, _ := cmd.Flags().GetInt("limit")

		if repo == "" {
			repo = lib.DetectRepoFromGit()
		}

		endpoints := []struct {
			name string
			path string
		}{
			{"sast", "/sast/findings"},
			{"sca_dependencies", "/sca/dependencies/findings"},
			{"sca_containers", "/sca/containers/findings"},
			{"secrets", "/secrets/findings"},
			{"pentest", "/dast/pentest/findings"},
			{"bughunt", "/dast/bughunt/findings"},
			{"cspm", "/cspm/findings"},
		}

		// Filter by type if specified
		if findingType != "" {
			filtered := []struct {
				name string
				path string
			}{}
			for _, ep := range endpoints {
				if ep.name == findingType {
					filtered = append(filtered, ep)
				}
			}
			if len(filtered) == 0 {
				fmt.Fprintf(os.Stderr, "Error: unknown finding type %q. Valid types: sast, sca_dependencies, sca_containers, secrets, pentest, bughunt, cspm\n", findingType)
				os.Exit(1)
			}
			endpoints = filtered
		}

		type findingResult struct {
			Type  string          `json:"type"`
			Error string          `json:"error,omitempty"`
			Data  json.RawMessage `json:"data,omitempty"`
		}

		var results []findingResult
		for _, ep := range endpoints {
			params := make([]string, 0)
			if severity != "" {
				params = append(params, "severity", severity)
			}
			if status != "" {
				params = append(params, "status", status)
			}
			if repo != "" {
				params = append(params, "repository", repo)
			}
			params = append(params, "limit", fmt.Sprintf("%d", limit))

			qs := buildFindingsQueryString(queryParams, params...)
			path := ep.path + qs

			resp, err := doFindingsGet(nullifyClient, path)
			if err != nil {
				results = append(results, findingResult{Type: ep.name, Error: err.Error()})
				continue
			}
			results = append(results, findingResult{Type: ep.name, Data: json.RawMessage(resp)})
		}

		output, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(output))
	},
}

func init() {
	rootCmd.AddCommand(findingsCmd)

	findingsCmd.Flags().String("severity", "", "Filter by severity (critical, high, medium, low)")
	findingsCmd.Flags().String("status", "", "Filter by status (open, fixed, false_positive)")
	findingsCmd.Flags().String("type", "", "Filter by type (sast, sca_dependencies, sca_containers, secrets, pentest, bughunt, cspm)")
	findingsCmd.Flags().String("repo", "", "Repository name (auto-detected from git if not set)")
	findingsCmd.Flags().Int("limit", 20, "Maximum results per finding type")
}

func buildFindingsQueryString(base map[string]string, extra ...string) string {
	parts := []string{}
	for k, v := range base {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	for i := 0; i+1 < len(extra); i += 2 {
		if extra[i+1] != "" {
			parts = append(parts, fmt.Sprintf("%s=%s", extra[i], extra[i+1]))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "?" + strings.Join(parts, "&")
}

func doFindingsGet(c *client.NullifyClient, path string) (string, error) {
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
		return "", fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}
