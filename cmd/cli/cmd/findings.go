package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/nullify-platform/cli/internal/findings"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
)

const findingsListLong = `Query and display security findings from all Nullify scanners.
Supports SAST, SCA (dependencies and containers), Secrets, Pentest, BugHunt, CSPM and SCPM.
Auto-detects the current repository from git if --repo is not specified, except for CSPM findings, which have no repository.
Results are paginated automatically up to --limit total findings.

The output reports total, returned and truncated. An empty result has total 0.
A truncated result has truncated true. A failure to read, such as no access,
exits with code 3 and is never an empty result.`

var findingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "List and act on security findings across all scanner types",
	Long:  findingsListLong,
	Example: `  # List all findings
  nullify findings

  # Filter by severity and type
  nullify findings --severity critical --type sast

  # Output as table
  nullify findings -o table --repo my-repo

  # Fetch up to 500 findings
  nullify findings --limit 500

  # Allowlist a CSPM finding that triage got wrong
  nullify findings allowlist abc123 --type cspm --allowlist-type UserFalsePositive --reason "Bucket is public by design"`,
	Args: cobra.NoArgs,
	RunE: runFindingsList,
}

var findingsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List security findings across all scanner types",
	Long:  findingsListLong,
	Example: `  # List CSPM findings from one UTC window
  nullify findings list --type cspm --from 2026-11-01T00:00:00Z --to 2026-11-02T00:00:00Z

  # List SCPM findings
  nullify findings list --type scpm --limit 500`,
	Args: cobra.NoArgs,
	RunE: runFindingsList,
}

func runFindingsList(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()

	severity, _ := cmd.Flags().GetString("severity")
	status, _ := cmd.Flags().GetString("status")
	findingType, _ := cmd.Flags().GetString("type")
	repo, _ := cmd.Flags().GetString("repo")
	from, _ := cmd.Flags().GetString("from")
	to, _ := cmd.Flags().GetString("to")
	limit, _ := cmd.Flags().GetInt("limit")
	debug, _ := cmd.Flags().GetBool("debug")

	opts := findings.SearchOptions{
		Severity: severity,
		Status:   status,
		From:     from,
		To:       to,
		Limit:    limit,
	}

	if findingType != "" {
		apiTypes, err := findings.APITypesFor(findingType)
		if err != nil {
			return err
		}
		opts.APITypes = apiTypes
	}
	opts.Repository = findingsRepository(repo, opts.APITypes, lib.DetectRepoFromGit)
	if debug {
		opts.Debug = os.Stderr
	}

	authCtx, err := resolveCommandAuth(ctx)
	if err != nil {
		return err
	}

	result, err := findings.Search(ctx, authCtx.APIClient(), opts)
	if err != nil {
		return findingsError(err)
	}

	if result.Truncated && !quiet {
		fmt.Fprintf(os.Stderr, "Showing %d of %d findings; raise --limit to read more\n", result.Returned, result.Total)
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if err := output.Print(cmd, out); err != nil {
		fmt.Fprintln(os.Stderr, string(out))
	}
	return nil
}

// findingsRepository returns the repository filter: the flag if set, otherwise the
// repository of the working directory for types that can belong to a repository.
func findingsRepository(flag string, apiTypes []string, detect func() string) string {
	if flag != "" || !findings.HasRepository(apiTypes) {
		return flag
	}
	return detect()
}

// findingsError sets the exit code for a failed finding operation: 1 for invalid
// input and 3 for an API failure, access failures included.
func findingsError(err error) error {
	for _, invalid := range []error{
		findings.ErrUnknownType, findings.ErrUnsupported, findings.ErrFindingIDRequired,
		findings.ErrReasonRequired, findings.ErrInvalidAllowlistType, findings.ErrInvalidVerdict,
		findings.ErrInvalidLimit, findings.ErrInvalidStatus, findings.ErrInvalidTimeout,
	} {
		if errors.Is(err, invalid) {
			return err
		}
	}
	return networkError("%w", err)
}

func addFindingsListFlags(cmd *cobra.Command) {
	cmd.Flags().String("severity", "", "Filter by severity (critical, high, medium, low)")
	cmd.Flags().String("status", "", "Filter by status ("+strings.Join(findings.Statuses, ", ")+")")
	cmd.Flags().String("type", "", "Filter by type ("+strings.Join(findings.Names(), ", ")+")")
	cmd.Flags().String("repo", "", "Repository name (auto-detected from git if not set, except for cspm)")
	cmd.Flags().String("from", "", "Only findings at or after this RFC 3339 UTC time")
	cmd.Flags().String("to", "", "Only findings at or before this RFC 3339 UTC time")
	cmd.Flags().Int("limit", 100, "Maximum total findings to return (fetches multiple pages as needed)")
	cmd.Flags().Bool("debug", false, "Print one line per page to stderr")
}

func init() {
	rootCmd.AddCommand(findingsCmd)
	addFindingsListFlags(findingsCmd)
	addFindingsListFlags(findingsListCmd)
	findingsCmd.AddCommand(findingsListCmd)
	addFindingVerbCommands(findingsCmd)
}

func addFindingVerbCommands(parent *cobra.Command) {
	for _, verb := range findings.Verbs {
		parent.AddCommand(newFindingVerbCommand(verb))
	}
	parent.AddCommand(newFindingFeedbackCommand(), newFindingGetFeedbackCommand())
}

func newFindingVerbCommand(verb findings.Verb) *cobra.Command {
	cmd := &cobra.Command{
		Use:   verb.Name + " <finding-id>",
		Short: verb.Description,
		Long:  verb.Description + "\n\nSupported types: " + strings.Join(verb.Types(), ", "),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			findingType, _ := cmd.Flags().GetString("type")
			reason, _ := cmd.Flags().GetString("reason")
			allowlistType, _ := cmd.Flags().GetString("allowlist-type")

			authCtx, err := resolveCommandAuth(cmd.Context())
			if err != nil {
				return err
			}

			data, err := verb.Run(cmd.Context(), authCtx.APIClient(), findingType, args[0], findings.Params{Reason: reason, AllowlistType: allowlistType})
			if err != nil {
				return findingsError(err)
			}
			return reportVerb(cmd, verb, findingType, data)
		},
	}

	cmd.Flags().String("type", "", "Finding type ("+strings.Join(verb.Types(), ", ")+")")
	_ = cmd.MarkFlagRequired("type")
	if verb.NeedsAllowlistType {
		cmd.Flags().String("allowlist-type", "", "Why the finding is allowlisted ("+strings.Join(findings.AllowlistTypes, ", ")+")")
		_ = cmd.MarkFlagRequired("allowlist-type")
	}
	if verb.NeedsReason {
		cmd.Flags().String("reason", "", "Human-readable reason")
		_ = cmd.MarkFlagRequired("reason")
	}
	return cmd
}

func reportVerb(cmd *cobra.Command, verb findings.Verb, findingType string, data []byte) error {
	if warning := verb.Warning(findingType); warning != "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Warning: "+warning)
	}
	return output.Print(cmd, data)
}

func newFindingFeedbackCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "feedback <finding-id>",
		Short: "Record feedback on a finding of any type. This never changes the finding.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			verdict, _ := cmd.Flags().GetString("verdict")
			comment, _ := cmd.Flags().GetString("comment")

			authCtx, err := resolveCommandAuth(cmd.Context())
			if err != nil {
				return err
			}

			data, err := findings.SubmitFeedback(cmd.Context(), authCtx.APIClient(), args[0], verdict, comment)
			if err != nil {
				return findingsError(err)
			}
			return output.Print(cmd, data)
		},
	}
	cmd.Flags().String("verdict", "", "Feedback verdict ("+strings.Join(findings.FeedbackVerdicts, ", ")+")")
	_ = cmd.MarkFlagRequired("verdict")
	cmd.Flags().String("comment", "", "Optional comment")
	return cmd
}

func newFindingGetFeedbackCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get-feedback <finding-id>",
		Short: "List the feedback recorded on a finding of any type",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			authCtx, err := resolveCommandAuth(cmd.Context())
			if err != nil {
				return err
			}

			data, err := findings.ListFeedback(cmd.Context(), authCtx.APIClient(), args[0])
			if err != nil {
				return findingsError(err)
			}
			return output.Print(cmd, data)
		},
	}
}
