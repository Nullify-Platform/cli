package commands

import (
	"fmt"
	"os"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/upload"
	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/spf13/cobra"
)

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
		// context command not found — create it (shouldn't happen normally)
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
		dryRun      bool
	)

	pushCmd := &cobra.Command{
		Use:   "push [files...]",
		Short: "Upload context data to Nullify",
		Long:  "Upload context data (Terraform plans, CI logs, etc.) to Nullify for infrastructure-aware security analysis.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			client := getClient()

			// Auto-detect git context
			gitCtx := lib.DetectGitContext()
			repo := gitCtx.Repository
			if repo == "" {
				return fmt.Errorf("could not detect repository from git remote — ensure you're in a git repo or set GITHUB_REPOSITORY")
			}

			// Use env var overrides (for CI environments)
			if envRepo := os.Getenv("GITHUB_REPOSITORY"); envRepo != "" {
				repo = envRepo
			}
			if branch == "" {
				branch = gitCtx.Branch
			}
			if branch == "" {
				if envBranch := os.Getenv("GITHUB_REF_NAME"); envBranch != "" {
					branch = envBranch
				}
			}
			commitSHA := gitCtx.CommitSHA
			if envSHA := os.Getenv("GITHUB_SHA"); envSHA != "" {
				commitSHA = envSHA
			}

			// Request scoped credentials
			credsReq := api.ContextCredentialsRequest{
				ContextType: contextType,
				Repository:  repo,
				Branch:      branch,
				Environment: environment,
				Name:        name,
				PRNumber:    prNumber,
				CommitSHA:   commitSHA,
			}

			if dryRun {
				fmt.Printf("Dry run — would upload %d file(s) as:\n", len(args))
				fmt.Printf("  Type:        %s\n", contextType)
				fmt.Printf("  Repository:  %s\n", repo)
				fmt.Printf("  Branch:      %s\n", branch)
				fmt.Printf("  Environment: %s\n", environment)
				fmt.Printf("  Name:        %s\n", name)
				if prNumber > 0 {
					fmt.Printf("  PR:          #%d\n", prNumber)
				}
				for _, f := range args {
					fmt.Printf("  File:        %s\n", f)
				}
				return nil
			}

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
				CommitSHA:   commitSHA,
				CLIVersion:  logger.Version,
			}

			for _, filePath := range args {
				logger.L(ctx).Info("uploading", logger.String("file", filePath))
				if err := uploader.Upload(ctx, filePath, metadata); err != nil {
					return fmt.Errorf("failed to upload %s: %w", filePath, err)
				}
				fmt.Printf("Uploaded %s → s3://%s/%slatest.json\n", filePath, creds.Bucket, creds.KeyPrefix)
			}

			return nil
		},
	}

	pushCmd.Flags().StringVar(&contextType, "type", "", "Context type (terraform, ci_logs, config, deploy, api_spec)")
	pushCmd.Flags().StringVar(&name, "name", "", "Logical name for this context (e.g. networking, ecs-api)")
	pushCmd.Flags().StringVar(&environment, "environment", "", "Deployment environment (development, staging, production, unknown)")
	pushCmd.Flags().StringVar(&branch, "branch", "", "Git branch (auto-detected if omitted)")
	pushCmd.Flags().IntVar(&prNumber, "pr-number", 0, "Pull request number")
	pushCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Log what would be uploaded without uploading")
	_ = pushCmd.MarkFlagRequired("type")
	_ = pushCmd.MarkFlagRequired("name")

	contextCmd.AddCommand(pushCmd)
}
