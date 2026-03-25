package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/upload"
	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/spf13/cobra"
)

const maxUploadSize = 50 << 20 // 50 MB

// RegisterContextPushCommand adds the 'push' subcommand to the existing 'context' command.
// Must be called after RegisterContextCommands.
func RegisterContextPushCommand(parent *cobra.Command, getClient func() *api.Client) {
	// Find the existing 'context' command registered by the generated code
	var contextCmd *cobra.Command
	for _, cmd := range parent.Commands() {
		if cmd.Name() == "context" {
			contextCmd = cmd
			break
		}
	}
	if contextCmd == nil {
		contextCmd = &cobra.Command{
			Use:   "context",
			Short: "Context ingestion commands",
		}
		parent.AddCommand(contextCmd)
	}

	var (
		contextType string
		name        string
		environment string
		branch      string
		prNumber    int
		fromPR      int
		dryRun      bool
	)

	pushCmd := &cobra.Command{
		Use:   "push [file]",
		Short: "Upload context data to Nullify",
		Long:  "Upload a single context file (Terraform plan, CI log, etc.) to Nullify for infrastructure-aware security analysis.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			filePath := args[0]

			// Validate file exists and is within size limit
			info, err := os.Stat(filePath)
			if err != nil {
				return fmt.Errorf("file not found: %s", filePath)
			}
			if info.Size() > maxUploadSize {
				return fmt.Errorf("file %s is %d MB, exceeds maximum of %d MB", filePath, info.Size()>>20, maxUploadSize>>20)
			}

			// Auto-detect git context — check CI env vars first, then git
			repo := os.Getenv("GITHUB_REPOSITORY")
			if repo == "" {
				repo = lib.DetectGitContext().Repository
			}
			if repo == "" {
				return fmt.Errorf("could not detect repository — set GITHUB_REPOSITORY or ensure you're in a git repo")
			}

			if branch == "" {
				branch = os.Getenv("GITHUB_REF_NAME")
			}
			if branch == "" {
				branch = lib.DetectGitContext().Branch
			}

			commitSHA := os.Getenv("GITHUB_SHA")
			if commitSHA == "" {
				commitSHA = lib.DetectGitContext().CommitSHA
			}

			// Auto-detect name from file path if not provided
			if name == "" {
				name = deriveNameFromPath(filePath)
			}

			// Request scoped credentials
			credsReq := api.ContextCredentialsRequest{
				ContextType: contextType,
				Repository:  repo,
				Branch:      branch,
				Environment: environment,
				Name:        name,
				PRNumber:    prNumber,
				FromPR:      fromPR,
				CommitSHA:   commitSHA,
			}

			if dryRun {
				fmt.Printf("Dry run — would upload:\n")
				fmt.Printf("  Type:        %s\n", contextType)
				fmt.Printf("  Repository:  %s\n", repo)
				fmt.Printf("  Branch:      %s\n", branch)
				fmt.Printf("  Environment: %s\n", environment)
				fmt.Printf("  Name:        %s\n", name)
				if prNumber > 0 {
					fmt.Printf("  PR:          #%d\n", prNumber)
				}
				if fromPR > 0 {
					fmt.Printf("  From PR:     #%d\n", fromPR)
				}
				fmt.Printf("  File:        %s (%d bytes)\n", filePath, info.Size())
				return nil
			}

			client := getClient()

			logger.L(ctx).Info("requesting upload credentials",
				logger.String("repository", repo),
				logger.String("contextType", contextType),
				logger.String("name", name),
			)

			creds, err := client.PostContextCredentials(ctx, credsReq)
			if err != nil {
				return fmt.Errorf("failed to get upload credentials: %w", err)
			}

			uploader := upload.NewS3Uploader(
				creds.Credentials.AccessKeyID,
				creds.Credentials.SecretAccessKey,
				creds.Credentials.SessionToken,
				creds.Region,
				creds.Bucket,
				creds.KeyPrefix,
				creds.KMSKeyARN,
			)

			metadata := upload.ContextMetadata{
				ContextType: contextType,
				Repository:  repo,
				Branch:      branch,
				Environment: environment,
				Name:        name,
				PRNumber:    prNumber,
				FromPR:      fromPR,
				CommitSHA:   commitSHA,
				CLIVersion:  logger.Version,
			}

			logger.L(ctx).Info("uploading", logger.String("file", filePath))
			if err := uploader.Upload(ctx, filePath, metadata); err != nil {
				return fmt.Errorf("failed to upload %s: %w", filePath, err)
			}
			fmt.Printf("Uploaded %s → s3://%s/%slatest.json\n", filePath, creds.Bucket, creds.KeyPrefix)

			return nil
		},
	}

	pushCmd.Flags().StringVar(&contextType, "type", "", "Context type (terraform, ci_logs, config, deploy, api_spec)")
	pushCmd.Flags().StringVar(&name, "name", "", "Logical name for this context (e.g. networking, ecs-api). Auto-detected from file path if omitted.")
	pushCmd.Flags().StringVar(&environment, "environment", "", "Deployment environment (development, staging, production, unknown)")
	pushCmd.Flags().StringVar(&branch, "branch", "", "Git branch (auto-detected if omitted)")
	pushCmd.Flags().IntVar(&prNumber, "pr-number", 0, "Pull request number")
	pushCmd.Flags().IntVar(&fromPR, "from-pr", 0, "PR number that originated this deployment (for merge-to-main uploads)")
	pushCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Log what would be uploaded without uploading")
	_ = pushCmd.MarkFlagRequired("type")

	contextCmd.AddCommand(pushCmd)
}

// deriveNameFromPath extracts a logical name from the file path.
// e.g. "infrastructure/networking/plan.json" → "infrastructure/networking"
// e.g. "plan.json" → "root"
func deriveNameFromPath(filePath string) string {
	dir := filepath.Dir(filePath)
	if dir == "." || dir == "/" || dir == "" {
		return "root"
	}
	// Clean and normalize
	return filepath.ToSlash(filepath.Clean(dir))
}
