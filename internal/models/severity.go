package models

import "fmt"

// Severity is a string-based enum describing the severity of a finding.
//
// It is a named string type so it marshals/unmarshals to and from JSON as the
// same lowercase strings used on the wire, with no custom (Un)MarshalJSON
// required.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// String returns the underlying wire string for the severity.
func (s Severity) String() string {
	return string(s)
}

// IsValid reports whether the severity is one of the known values.
func (s Severity) IsValid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	default:
		return false
	}
}

// ParseSeverity converts a raw string into a Severity, rejecting unknown
// values. Use it at trust boundaries where input must be validated.
func ParseSeverity(s string) (Severity, error) {
	sev := Severity(s)
	if !sev.IsValid() {
		return "", fmt.Errorf("invalid severity %q", s)
	}
	return sev, nil
}
