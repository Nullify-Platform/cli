package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/nullify-platform/cli/internal/logger"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
)

var threatCmd = &cobra.Command{
	Use:   "threat",
	Short: "Manage threat investigations",
	Long:  "List, inspect, and create threat investigations.",
}

var threatListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List threat investigations",
	Example: "  nullify threat list",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger(cmd.Context())
		defer logger.Close(ctx)

		apiClient := getAPIClient()

		result, err := apiClient.ListManagerThreatInvestigations(ctx, url.Values{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := output.Print(cmd, result); err != nil {
			fmt.Fprintln(os.Stderr, string(result))
		}
	},
}

var threatGetCmd = &cobra.Command{
	Use:     "get <id>",
	Short:   "Get a threat investigation by ID",
	Args:    cobra.ExactArgs(1),
	Example: "  nullify threat get ti-123",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger(cmd.Context())
		defer logger.Close(ctx)

		apiClient := getAPIClient()

		params := url.Values{}
		params.Set("threatInvestigationId", args[0])

		result, err := apiClient.GetManagerThreatInvestigationsThreatInvestigationId(ctx, params)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := output.Print(cmd, result); err != nil {
			fmt.Fprintln(os.Stderr, string(result))
		}
	},
}

var threatCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a threat investigation",
	Example: "  nullify threat create --title \"Log4Shell\" --severity critical\n" +
		"  nullify threat create --title \"CVE sweep\" --cve-ids CVE-2021-44228,CVE-2021-45046",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger(cmd.Context())
		defer logger.Close(ctx)

		title, _ := cmd.Flags().GetString("title")
		description, _ := cmd.Flags().GetString("description")
		severity, _ := cmd.Flags().GetString("severity")
		advice, _ := cmd.Flags().GetString("advice")
		ecosystem, _ := cmd.Flags().GetString("ecosystem")
		keywords, _ := cmd.Flags().GetString("keywords")
		cvss, _ := cmd.Flags().GetString("cvss")
		cveIDs, _ := cmd.Flags().GetString("cve-ids")
		articleLinks, _ := cmd.Flags().GetString("article-links")

		body := map[string]any{
			"title": title,
		}
		if description != "" {
			body["description"] = description
		}
		if severity != "" {
			body["severity"] = severity
		}
		if advice != "" {
			body["advice"] = advice
		}
		if ecosystem != "" {
			body["ecosystem"] = ecosystem
		}
		if keywords != "" {
			body["keywords"] = keywords
		}
		if cvss != "" {
			body["cvss"] = cvss
		}
		if cveIDs != "" {
			body["cveIds"] = splitCSV(cveIDs)
		}
		if articleLinks != "" {
			body["articleLinks"] = splitCSV(articleLinks)
		}

		bodyBytes, err := json.Marshal(body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		apiClient := getAPIClient()

		result, err := apiClient.CreateManagerThreatInvestigations(ctx, url.Values{}, bytes.NewReader(bodyBytes))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := output.Print(cmd, result); err != nil {
			fmt.Fprintln(os.Stderr, string(result))
		}
	},
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func init() {
	rootCmd.AddCommand(threatCmd)
	threatCmd.AddCommand(threatListCmd)
	threatCmd.AddCommand(threatGetCmd)
	threatCmd.AddCommand(threatCreateCmd)

	threatCreateCmd.Flags().String("title", "", "Title of the threat investigation (required)")
	threatCreateCmd.Flags().String("description", "", "Description of the threat")
	threatCreateCmd.Flags().String("severity", "", "Severity of the threat")
	threatCreateCmd.Flags().String("advice", "", "Remediation advice")
	threatCreateCmd.Flags().String("ecosystem", "", "Affected ecosystem")
	threatCreateCmd.Flags().String("keywords", "", "Search keywords")
	threatCreateCmd.Flags().String("cvss", "", "CVSS score")
	threatCreateCmd.Flags().String("cve-ids", "", "Comma-separated list of CVE IDs")
	threatCreateCmd.Flags().String("article-links", "", "Comma-separated list of article links")
	_ = threatCreateCmd.MarkFlagRequired("title")
}
