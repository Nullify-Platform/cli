// Hand-written, not generated: scan-file has no OpenAPI operation to
// generate a client from (it never calls the Nullify API — see
// internal/scanfile's package doc for why, and for what engine it wraps).
// It follows the same RegisterXxxCommand(parent, ...) shape as this
// package's other hand-written files (context_push.go, pentest_bridge.go).
package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/nullify-platform/cli/internal/scanfile"
)

// RegisterScanFileCommand adds the 'scan-file' subcommand to parent (the
// hand-written top-level 'secrets' command; see cmd/cli/cmd/secrets.go).
func RegisterScanFileCommand(parent *cobra.Command) {
	var (
		flagStdin      bool
		flagPath       string
		flagRepository string
	)

	cmd := &cobra.Command{
		Use:   "scan-file [path]",
		Short: "Scan a single file (or stdin buffer) for secrets and print normalized findings",
		Long: `Scan a single file for hardcoded secrets and print normalized findings as a
JSON array on stdout. All matching runs in-process: no network call is made
and file content never leaves the machine.

This is the fast-local scan the IDE extension runs on save. It scans only
the given file (or the buffer piped on stdin via --stdin), never a whole
repo, and emits engine-agnostic findings.

Examples:
  # Scan a file on disk
  nullify secrets scan-file ./config.go

  # Scan an unsaved editor buffer (the editor pipes the buffer, --path labels it)
  cat buffer.go | nullify secrets scan-file --stdin --path ./config.go`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				content []byte
				path    string
				err     error
			)

			if flagStdin {
				if flagPath == "" {
					return fmt.Errorf("--path is required when using --stdin")
				}
				if len(args) > 0 {
					return fmt.Errorf("cannot combine a positional path with --stdin")
				}
				content, err = io.ReadAll(cmd.InOrStdin())
				if err != nil {
					return fmt.Errorf("failed to read stdin: %w", err)
				}
				path = flagPath
			} else {
				if len(args) != 1 {
					return fmt.Errorf("exactly one file path is required (or use --stdin)")
				}
				path = args[0]
				content, err = os.ReadFile(path)
				if err != nil {
					return fmt.Errorf("failed to read %s: %w", path, err)
				}
			}

			findings := scanfile.ScanContent(content, path, flagRepository)

			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			if err := enc.Encode(findings); err != nil {
				return fmt.Errorf("failed to encode findings: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&flagStdin, "stdin", false, "read the file content from stdin instead of disk")
	cmd.Flags().StringVar(&flagPath, "path", "", "path to label the scanned content with (required with --stdin)")
	cmd.Flags().StringVar(&flagRepository, "repository", "", "repository identifier folded into the correlation fingerprint")

	parent.AddCommand(cmd)
}
