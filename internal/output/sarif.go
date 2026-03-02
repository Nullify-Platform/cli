package output

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SARIF v2.1.0 types (minimal subset for findings output)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type sarifResult struct {
	RuleID  string       `json:"ruleId,omitempty"`
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

func severityToSARIFLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info", "informational":
		return "note"
	default:
		return "warning"
	}
}

func printSARIF(data []byte) error {
	// Try to parse as an array of finding-like objects
	var findings []map[string]any
	if err := json.Unmarshal(data, &findings); err != nil {
		// Try as wrapped type results
		var typeResults []struct {
			Type  string          `json:"type"`
			Error string          `json:"error,omitempty"`
			Data  json.RawMessage `json:"data,omitempty"`
		}
		if err2 := json.Unmarshal(data, &typeResults); err2 != nil {
			return fmt.Errorf("cannot convert data to SARIF format: %w", err)
		}

		// Flatten type results into findings
		for _, tr := range typeResults {
			if tr.Error != "" || len(tr.Data) == 0 {
				continue
			}
			var items []map[string]any
			if err := json.Unmarshal(tr.Data, &items); err != nil {
				// Try as {items: [...]}
				var wrapped struct {
					Items []map[string]any `json:"items"`
				}
				if err2 := json.Unmarshal(tr.Data, &wrapped); err2 == nil {
					items = wrapped.Items
				}
			}
			for i := range items {
				items[i]["_type"] = tr.Type
			}
			findings = append(findings, items...)
		}
	}

	var results []sarifResult
	for _, f := range findings {
		severity, _ := f["severity"].(string)
		title, _ := f["title"].(string)
		description, _ := f["description"].(string)
		ruleID, _ := f["rule_id"].(string)
		if ruleID == "" {
			ruleID, _ = f["id"].(string)
		}

		msg := title
		if description != "" && msg != description {
			msg = title + ": " + description
		}
		if msg == "" {
			msg = "Security finding"
		}

		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   severityToSARIFLevel(severity),
			Message: sarifMessage{Text: msg},
		})
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{Name: "Nullify"},
				},
				Results: results,
			},
		},
	}

	out, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}
