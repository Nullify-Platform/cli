package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func reportError(
	cmd *cobra.Command,
	err error,
	format string,
	args ...any,
) error {
	fmt.Fprintf(cmd.ErrOrStderr(), format, args...)
	cmd.SilenceErrors = true
	return err
}
