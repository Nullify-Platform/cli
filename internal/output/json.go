package output

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func printJSON(data []byte) error {
	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", "  "); err != nil {
		// If indenting fails, print raw
		fmt.Println(string(data))
		return nil
	}
	fmt.Println(buf.String())
	return nil
}
