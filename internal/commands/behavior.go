package commands

import "github.com/spf13/cobra"

const (
	preserveRuntimeUsageAnnotation = "nullify.preserve-runtime-usage"
	routeAnnotation                = "nullify.route"
)

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

func setRoute(cmd *cobra.Command, route string) {
	cmd.Annotations[routeAnnotation] = route
}

// Route returns the "METHOD /path" that a generated command calls, or an empty
// string for a command that is not generated.
func Route(cmd *cobra.Command) string {
	return cmd.Annotations[routeAnnotation]
}
