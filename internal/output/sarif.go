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
	Name    string      `json:"name"`
	Version string      `json:"version,omitempty"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID string `json:"id"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId,omitempty"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
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

// firstString returns the first non-empty string value found among the given keys.
func firstString(f map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := f[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// firstInt returns the first integer-like value found among the given keys.
// JSON numbers decode to float64; numeric strings are also accepted.
func firstInt(f map[string]any, keys ...string) (int, bool) {
	for _, k := range keys {
		switch v := f[k].(type) {
		case float64:
			return int(v), true
		case int:
			return v, true
		case json.Number:
			if n, err := v.Int64(); err == nil {
				return int(n), true
			}
		}
	}
	return 0, false
}

// buildLocation extracts a SARIF location from common location field shapes.
// Returns nil if no usable location data is present.
func buildLocation(f map[string]any) *sarifLocation {
	uri := firstString(f, "filePath", "file", "path", "uri", "url", "location")
	if uri == "" {
		return nil
	}

	loc := &sarifLocation{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: uri},
		},
	}

	if line, ok := firstInt(f, "startLine", "line", "lineNumber"); ok && line > 0 {
		loc.PhysicalLocation.Region = &sarifRegion{StartLine: line}
	}

	return loc
}

// unwrapFindings normalises the various JSON envelopes the CLI emits into a
// flat slice of finding-like objects:
//   - a top-level array: [ {...}, {...} ]
//   - the findings command object: { "findings": [...], "total": N }
//   - wrapped per-type results: [ { "type": ..., "data": [...] }, ... ]
func unwrapFindings(data []byte) []map[string]any {
	// 1. { "findings": [...], "total": N }
	var obj struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(data, &obj); err == nil && obj.Findings != nil {
		return obj.Findings
	}

	// 2. Top-level array. This may be a plain array of findings or an array of
	// wrapped per-type results ([{type, data:[...]}, ...]). Detect the wrapper
	// shape and unwrap it; otherwise treat the array as findings directly.
	var arr []map[string]any
	if err := json.Unmarshal(data, &arr); err == nil {
		if wrapped := unwrapTypeResults(data); wrapped != nil {
			return wrapped
		}
		return arr
	}

	// 3. Wrapped per-type results that aren't a plain array of objects.
	if wrapped := unwrapTypeResults(data); wrapped != nil {
		return wrapped
	}

	return nil
}

// unwrapTypeResults flattens the wrapped per-type results envelope
// ([{type, error, data:[...]}, ...]) into a flat findings slice. It returns nil
// when the data is not that shape (e.g. it's a plain findings array).
func unwrapTypeResults(data []byte) []map[string]any {
	var typeResults []struct {
		Type  string          `json:"type"`
		Error string          `json:"error,omitempty"`
		Data  json.RawMessage `json:"data,omitempty"`
	}
	if err := json.Unmarshal(data, &typeResults); err != nil {
		return nil
	}

	// Only treat this as the wrapper shape if at least one element actually
	// carries a typed data payload; otherwise it's a plain findings array.
	hasWrapper := false
	for _, tr := range typeResults {
		if tr.Type != "" || len(tr.Data) > 0 {
			hasWrapper = true
			break
		}
	}
	if !hasWrapper {
		return nil
	}

	var out []map[string]any
	for _, tr := range typeResults {
		if tr.Error != "" || len(tr.Data) == 0 {
			continue
		}
		var items []map[string]any
		if err := json.Unmarshal(tr.Data, &items); err != nil {
			var wrapped struct {
				Items []map[string]any `json:"items"`
			}
			if err2 := json.Unmarshal(tr.Data, &wrapped); err2 == nil {
				items = wrapped.Items
			}
		}
		for i := range items {
			if items[i] != nil {
				items[i]["_type"] = tr.Type
			}
		}
		out = append(out, items...)
	}
	return out
}

// buildSARIF converts CLI finding JSON into a SARIF v2.1.0 document.
func buildSARIF(data []byte) (sarifLog, error) {
	findings := unwrapFindings(data)
	if findings == nil {
		return sarifLog{}, fmt.Errorf("cannot convert data to SARIF format: unrecognized JSON shape")
	}

	var results []sarifResult
	ruleSeen := map[string]bool{}
	var rules []sarifRule

	for _, f := range findings {
		if f == nil {
			continue
		}

		severity := firstString(f, "severity")
		title := firstString(f, "title")
		description := firstString(f, "description")
		ruleID := firstString(f, "rule_id", "ruleId", "id")

		msg := title
		if description != "" && msg != description {
			if msg != "" {
				msg = title + ": " + description
			} else {
				msg = description
			}
		}
		if msg == "" {
			msg = "Security finding"
		}

		result := sarifResult{
			RuleID:  ruleID,
			Level:   severityToSARIFLevel(severity),
			Message: sarifMessage{Text: msg},
		}
		if loc := buildLocation(f); loc != nil {
			result.Locations = []sarifLocation{*loc}
		}
		results = append(results, result)

		if ruleID != "" && !ruleSeen[ruleID] {
			ruleSeen[ruleID] = true
			rules = append(rules, sarifRule{ID: ruleID})
		}
	}

	return sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{Name: "Nullify", Rules: rules},
				},
				Results: results,
			},
		},
	}, nil
}

// SARIFBytes converts CLI finding JSON into an indented SARIF document.
// Exported so other commands (e.g. `ci report --format sarif`) can reuse it.
func SARIFBytes(data []byte) ([]byte, error) {
	log, err := buildSARIF(data)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(log, "", "  ")
}

func printSARIF(data []byte) error {
	out, err := SARIFBytes(data)
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}
