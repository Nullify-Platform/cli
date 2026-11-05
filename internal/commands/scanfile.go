package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/nullify-platform/cli/internal/scanfile"
)

// RegisterScanFileCommand adds a local secret scan command to parent.
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

Scan a file on disk or pipe a buffer with --stdin. Results contain secret
types and locations. Secret values are not included.

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
