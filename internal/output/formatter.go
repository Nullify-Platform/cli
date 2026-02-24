package output

import (
	"encoding/json"

	"github.com/spf13/cobra"
)

// Print formats and prints data based on the --output flag value.
func Print(cmd *cobra.Command, data []byte) error {
	format, _ := cmd.Flags().GetString("output")
	switch format {
	case "json":
		return printJSON(data)
	case "yaml":
		return printYAML(data)
	case "table":
		return printTable(data)
	default:
		return printJSON(data)
	}
}

// isArray checks if JSON data is an array.
func isArray(data []byte) bool {
	var raw json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return false
	}
	return len(raw) > 0 && raw[0] == '['
}
