package cmd

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			return err
		}
		apiClient := authCtx.APIClient()

		result, err := apiClient.ListManagerThreatInvestigations(ctx, api.ListManagerThreatInvestigationsInput{})
		if err != nil {
			return err
		}

		data, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if err := output.Print(cmd, data); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), string(data))
		}
		return nil
	},
}

var threatGetCmd = &cobra.Command{
	Use:     "get <id>",
	Short:   "Get a threat investigation by ID",
	Args:    cobra.ExactArgs(1),
	Example: "  nullify threat get ti-123",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			return err
		}
		apiClient := authCtx.APIClient()

		result, err := apiClient.GetManagerThreatInvestigationsThreatInvestigationId(ctx, api.GetManagerThreatInvestigationsThreatInvestigationIdInput{
			ThreatInvestigationID: args[0],
		})
		if err != nil {
			return err
		}

		data, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if err := output.Print(cmd, data); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), string(data))
		}
		return nil
	},
}

var threatCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a threat investigation",
	Example: "  nullify threat create --title \"Log4Shell\" --severity critical\n" +
		"  nullify threat create --title \"CVE sweep\" --cve-ids CVE-2021-44228,CVE-2021-45046",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		in, err := buildThreatInput(cmd.Flags())
		if err != nil {
			return err
		}

		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			return err
		}
		apiClient := authCtx.APIClient()

		result, err := apiClient.CreateManagerThreatInvestigations(ctx, in)
		if err != nil {
			return err
		}

		data, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if err := output.Print(cmd, data); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), string(data))
		}
		return nil
	},
}

// threatSeverities are the severities a threat investigation takes. The
// server stores --severity as sent, and its enum is upper case.
var threatSeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}

// buildThreatInput reads the `threat create` flags into the request.
func buildThreatInput(flags *pflag.FlagSet) (api.CreateManagerThreatInvestigationsInput, error) {
	str := func(name string) string {
		v, _ := flags.GetString(name)
		return v
	}
	optional := func(name string) *string {
		if v := str(name); v != "" {
			return &v
		}
		return nil
	}

	in := api.CreateManagerThreatInvestigationsInput{
		Title:       str("title"),
		Description: optional("description"),
		Advice:      optional("advice"),
		Ecosystem:   optional("ecosystem"),
		Keywords:    optional("keywords"),
	}
	if severity := str("severity"); severity != "" {
		normalized, err := normalizeThreatSeverity(severity)
		if err != nil {
			return in, err
		}
		in.Severity = &normalized
	}
	if cvss := str("cvss"); cvss != "" {
		cvssFloat, err := strconv.ParseFloat(cvss, 64)
		if err != nil {
			return in, fmt.Errorf("invalid --cvss %q: %w", cvss, err)
		}
		in.Cvss = &cvssFloat
	}
	if cveIDs := str("cve-ids"); cveIDs != "" {
		in.CveIds = splitCSV(cveIDs)
	}
	if articleLinks := str("article-links"); articleLinks != "" {
		in.ArticleLinks = splitCSV(articleLinks)
	}
	return in, nil
}

// normalizeThreatSeverity upper-cases a severity and checks it is one of
// threatSeverities.
func normalizeThreatSeverity(severity string) (string, error) {
	normalized := strings.ToUpper(strings.TrimSpace(severity))
	if slices.Contains(threatSeverities, normalized) {
		return normalized, nil
	}
	return "", fmt.Errorf("invalid --severity %q: must be one of %s",
		severity, strings.ToLower(strings.Join(threatSeverities, ", ")))
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

	addThreatCreateFlags(threatCreateCmd.Flags())
	_ = threatCreateCmd.MarkFlagRequired("title")
}

func addThreatCreateFlags(flags *pflag.FlagSet) {
	flags.String("title", "", "Title of the threat investigation (required)")
	flags.String("description", "", "Description of the threat")
	flags.String("severity", "", "Severity of the threat: critical, high, medium, low or informational")
	flags.String("advice", "", "Remediation advice")
	flags.String("ecosystem", "", "Affected ecosystem")
	flags.String("keywords", "", "Search keywords")
	flags.String("cvss", "", "CVSS score")
	flags.String("cve-ids", "", "Comma-separated list of CVE IDs")
	flags.String("article-links", "", "Comma-separated list of article links")
}
