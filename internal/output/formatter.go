package output

import (
	"encoding/json"
	"fmt"
	"os"

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
	case "sarif":
		return printSARIF(data)
	default:
		return printJSON(data)
	}
}

// Msg prints an informational message to stderr unless --quiet is set.
func Msg(cmd *cobra.Command, format string, args ...any) {
	q, _ := cmd.Flags().GetBool("quiet")
	if q {
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// isArray checks if JSON data is an array.
func isArray(data []byte) bool {
	var raw json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return false
	}
	return len(raw) > 0 && raw[0] == '['
}
