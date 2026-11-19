package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// severityLevel orders finding severities for the gate threshold. Unknown
// ranks above critical: a finding whose severity cannot be read meets every
// threshold, so the gate blocks on it rather than passing it unseen.
type severityLevel int

const (
	severityInformational severityLevel = iota
	severityLow
	severityMedium
	severityHigh
	severityCritical
	severityUnknown
)

// reportSeverities is the order in which the report lists severities.
var reportSeverities = []severityLevel{
	severityCritical, severityHigh, severityMedium, severityLow,
	severityInformational, severityUnknown,
}

// thresholdNames are the values --severity-threshold accepts, most severe first.
var thresholdNames = []string{"critical", "high", "medium", "low"}

var errInvalidSeverityThreshold = errors.New("invalid --severity-threshold")

func (l severityLevel) String() string {
	switch l {
	case severityInformational:
		return "informational"
	case severityLow:
		return "low"
	case severityMedium:
		return "medium"
	case severityHigh:
		return "high"
	case severityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// meets reports whether a finding of this severity is at or above threshold.
func (l severityLevel) meets(threshold severityLevel) bool {
	return l >= threshold
}

// parseSeverity reads a severity value as the API writes it. A value the CLI
// does not recognise is unknown.
func parseSeverity(value string) severityLevel {
	switch strings.ToUpper(value) {
	case "CRITICAL":
		return severityCritical
	case "HIGH":
		return severityHigh
	case "MEDIUM":
		return severityMedium
	case "LOW":
		return severityLow
	case "INFORMATIONAL", "INFO", "NONE":
		return severityInformational
	default:
		return severityUnknown
	}
}

// parseSeverityThreshold reads the --severity-threshold flag value.
func parseSeverityThreshold(value string) (severityLevel, error) {
	for _, name := range thresholdNames {
		if strings.EqualFold(value, name) {
			return parseSeverity(name), nil
		}
	}
	return severityUnknown, fmt.Errorf(
		"%w %q. Valid values: %s",
		errInvalidSeverityThreshold, value, strings.Join(thresholdNames, ", "),
	)
}

// findingSeverity reads a finding's severity from the first of the scanner's
// severity fields that holds a non-empty string. A scanner with no severity
// field, or a finding that has none, gives unknown.
func findingSeverity(ep scannerEndpoint, finding json.RawMessage) severityLevel {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(finding, &fields); err != nil {
		return severityUnknown
	}
	for _, name := range ep.severityFields {
		var value string
		if err := json.Unmarshal(fields[name], &value); err == nil && value != "" {
			return parseSeverity(value)
		}
	}
	return severityUnknown
}
