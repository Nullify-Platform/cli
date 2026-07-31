package commands

import "github.com/spf13/cobra"

const preserveRuntimeUsageAnnotation = "nullify.preserve-runtime-usage"

func preserveRuntimeUsage(cmd *cobra.Command) {
	if cmd.Annotations == nil {
		cmd.Annotations = make(map[string]string)
	}
	cmd.Annotations[preserveRuntimeUsageAnnotation] = "true"
}

// PreservesRuntimeUsage reports whether runtime errors should include usage.
func PreservesRuntimeUsage(cmd *cobra.Command) bool {
	return cmd.Annotations[preserveRuntimeUsageAnnotation] == "true"
}
