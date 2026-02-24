package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
)

func printTable(data []byte) error {
	if isArray(data) {
		return printArrayTable(data)
	}
	return printObjectTable(data)
}

func printArrayTable(data []byte) error {
	var items []map[string]any
	if err := json.Unmarshal(data, &items); err != nil {
		// Try as array of primitives
		fmt.Println(string(data))
		return nil
	}
	if len(items) == 0 {
		fmt.Println("No results")
		return nil
	}

	// Collect all keys from all items
	keySet := make(map[string]bool)
	for _, item := range items {
		for k := range item {
			keySet[k] = true
		}
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	// Header
	fmt.Fprintln(w, strings.Join(toUpperKeys(keys), "\t"))
	// Rows
	for _, item := range items {
		vals := make([]string, len(keys))
		for i, k := range keys {
			vals[i] = formatValue(item[k])
		}
		fmt.Fprintln(w, strings.Join(vals, "\t"))
	}
	return w.Flush()
}

func printObjectTable(data []byte) error {
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		fmt.Println(string(data))
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "KEY\tVALUE")
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s\t%s\n", k, formatValue(obj[k]))
	}
	return w.Flush()
}

func toUpperKeys(keys []string) []string {
	upper := make([]string, len(keys))
	for i, k := range keys {
		upper[i] = strings.ToUpper(k)
	}
	return upper
}

func formatValue(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case bool:
		return fmt.Sprintf("%t", val)
	case []any:
		return fmt.Sprintf("[%d items]", len(val))
	case map[string]any:
		return fmt.Sprintf("{%d keys}", len(val))
	default:
		return fmt.Sprintf("%v", val)
	}
}
