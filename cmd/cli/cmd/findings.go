package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/logger"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
)

var findingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "List security findings across all scanner types",
	Long: `Query and display security findings from all Nullify scanners.
Supports SAST, SCA (dependencies and containers), Secrets, Pentest, BugHunt, and CSPM.
Auto-detects the current repository from git if --repo is not specified.
Results are paginated automatically up to --limit total findings.`,
	Example: `  # List all findings
  nullify findings

  # Filter by severity and type
  nullify findings --severity critical --type sast

  # Output as table
  nullify findings -o table --repo my-repo

  # Fetch up to 500 findings
  nullify findings --limit 500`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger(cmd.Context())
		defer logger.Close(ctx)

		findingsHost := resolveHost(ctx)
		token, err := lib.GetNullifyToken(ctx, findingsHost, nullifyToken, githubToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: not authenticated. Run 'nullify auth login' first.\n")
			os.Exit(ExitAuthError)
		}

		nullifyClient := client.NewNullifyClient(findingsHost, token)

		creds, err := auth.LoadCredentials()
		queryParams := map[string]string{}
		if err == nil {
			if hostCreds, ok := creds[auth.CredentialKey(findingsHost)]; ok && hostCreds.QueryParameters != nil {
				queryParams = hostCreds.QueryParameters
			}
		}

		severity, _ := cmd.Flags().GetString("severity")
		status, _ := cmd.Flags().GetString("status")
		findingType, _ := cmd.Flags().GetString("type")
		repo, _ := cmd.Flags().GetString("repo")
		limit, _ := cmd.Flags().GetInt("limit")
		debug, _ := cmd.Flags().GetBool("debug")

		if repo == "" {
			repo = lib.DetectRepoFromGit()
		}

		qs := lib.BuildQueryString(queryParams)
		path := "/admin/findings" + qs

		type findingsOutput struct {
			Findings []json.RawMessage `json:"findings"`
			Total    int               `json:"total"`
		}

		type unifiedResponse struct {
			Findings    []json.RawMessage `json:"findings"`
			Total       int               `json:"total"`
			HasMoreData bool              `json:"hasMoreData"`
			ScrollID    *string           `json:"scrollId"`
		}

		allFindings := make([]json.RawMessage, 0)
		var scrollID string
		var lastTotal int

		for {
			pageSize := 100
			remaining := limit - len(allFindings)
			if remaining <= 0 {
				break
			}
			if remaining < pageSize {
				pageSize = remaining
			}

			query := map[string]any{
				"pageSize": pageSize,
			}
			if repo != "" {
				query["repository"] = []string{repo}
			}
			if severity != "" {
				query["severity"] = []string{severity}
			}
			if findingType != "" {
				query["type"] = []string{findingType}
			}
			if scrollID != "" {
				query["scrollId"] = scrollID
			}
			if status != "" {
				switch status {
				case "open":
					f := false
					query["isResolved"] = f
				case "fixed":
					t := true
					query["isFixed"] = t
				case "false_positive":
					t := true
					query["isFalsePositive"] = t
				case "accepted_risk":
					t := true
					query["isAllowlisted"] = t
				}
			}

			reqBody := map[string]any{"query": query}
			bodyBytes, err := json.Marshal(reqBody)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(ExitNetworkError)
			}

			if debug {
				fmt.Fprintf(os.Stderr, "[debug] POST %s%s\n", nullifyClient.BaseURL, path)
				fmt.Fprintf(os.Stderr, "[debug] body: %s\n", string(bodyBytes))
			}

			respBody, err := lib.DoPostJSON(ctx, nullifyClient.HttpClient, nullifyClient.BaseURL, path, bytes.NewReader(bodyBytes))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(ExitNetworkError)
			}

			if debug {
				preview := respBody
				if len(preview) > 500 {
					preview = preview[:500] + "..."
				}
				fmt.Fprintf(os.Stderr, "[debug] response: %s\n", preview)
			}

			var resp unifiedResponse
			if err := json.Unmarshal([]byte(respBody), &resp); err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
				os.Exit(ExitNetworkError)
			}

			allFindings = append(allFindings, resp.Findings...)
			lastTotal = resp.Total

			if debug {
				fmt.Fprintf(os.Stderr, "[debug] page fetched: %d findings, hasMoreData=%v, total=%d\n", len(resp.Findings), resp.HasMoreData, resp.Total)
			}

			if !resp.HasMoreData || resp.ScrollID == nil || *resp.ScrollID == "" {
				break
			}
			scrollID = *resp.ScrollID
		}

		result := findingsOutput{
			Findings: allFindings,
			Total:    lastTotal,
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		if err := output.Print(cmd, out); err != nil {
			fmt.Fprintln(os.Stderr, string(out))
		}
	},
}

func init() {
	rootCmd.AddCommand(findingsCmd)

	findingsCmd.Flags().String("severity", "", "Filter by severity (critical, high, medium, low)")
	findingsCmd.Flags().String("status", "", "Filter by status (open, fixed, false_positive, accepted_risk)")
	findingsCmd.Flags().String("type", "", "Filter by type (sast, sca_dependencies, sca_containers, secrets, pentest, bughunt, cspm)")
	findingsCmd.Flags().String("repo", "", "Repository name (auto-detected from git if not set)")
	findingsCmd.Flags().Int("limit", 100, "Maximum total findings to return (fetches multiple pages as needed)")
	findingsCmd.Flags().Bool("debug", false, "Print request URLs, bodies, and responses to stderr")
}
