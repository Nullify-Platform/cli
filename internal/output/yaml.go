package output

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

func printYAML(data []byte) error {
	var obj any
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	out, err := yaml.Marshal(obj)
	if err != nil {
		return fmt.Errorf("failed to convert to YAML: %w", err)
	}
	fmt.Print(string(out))
	return nil
}
