package cmd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func scannerByName(t *testing.T, name string) scannerEndpoint {
	t.Helper()
	for _, ep := range allScannerEndpoints() {
		if ep.name == name {
			return ep
		}
	}
	t.Fatalf("no scanner %q", name)
	return scannerEndpoint{}
}

func TestFindingSeverity(t *testing.T) {
	tests := []struct {
		scanner string
		finding string
		want    severityLevel
	}{
		{"sast", `{"severity":"CRITICAL"}`, severityCritical},
		{"sast", `{"severity":"low"}`, severityLow},
		{"sca_dependencies", `{"vulnerabilitiesMaxSeverity":"HIGH","severity":"LOW"}`, severityHigh},
		{"sca_containers", `{"vulnerabilitiesMaxSeverity":"MEDIUM"}`, severityMedium},
		{"sca_containers", `{"vulnerabilitiesMaxSeverity":"INFORMATIONAL"}`, severityInformational},
		{"sca_dependencies", `{"vulnerabilitiesMaxSeverity":"UNKNOWN"}`, severityUnknown},
		{"secrets", `{"priorityLabel":"LOW"}`, severityUnknown},
		{"pentest", `{"effectiveSeverity":"LOW","severity":"CRITICAL"}`, severityLow},
		{"pentest", `{"severity":"CRITICAL"}`, severityCritical},
		{"bughunt", `{"severityOverride":"LOW","severity":"CRITICAL"}`, severityLow},
		{"bughunt", `{"severityOverride":"","severity":"HIGH"}`, severityHigh},
		{"cspm", `{"severity":"NONE"}`, severityInformational},
		{"cspm", `{}`, severityUnknown},
		{"sast", `{"severity":7}`, severityUnknown},
		{"sast", `not json`, severityUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.scanner+" "+tt.finding, func(t *testing.T) {
			got := findingSeverity(scannerByName(t, tt.scanner), json.RawMessage(tt.finding))
			require.Equal(t, tt.want, got)
		})
	}
}

func TestSeverityThreshold(t *testing.T) {
	tests := []struct {
		threshold string
		finding   severityLevel
		blocks    bool
	}{
		{"critical", severityCritical, true},
		{"critical", severityHigh, false},
		{"critical", severityLow, false},
		{"critical", severityUnknown, true},
		{"high", severityHigh, true},
		{"high", severityMedium, false},
		{"low", severityLow, true},
		{"low", severityInformational, false},
		{"low", severityUnknown, true},
	}
	for _, tt := range tests {
		t.Run(tt.threshold+" "+tt.finding.String(), func(t *testing.T) {
			threshold, err := parseSeverityThreshold(tt.threshold)
			require.NoError(t, err)
			require.Equal(t, tt.blocks, tt.finding.meets(threshold))
		})
	}
}

func TestParseSeverityThresholdRejectsOtherValues(t *testing.T) {
	for _, value := range []string{"", "unknown", "informational", "CRITICAL ", "severe"} {
		t.Run(value, func(t *testing.T) {
			_, err := parseSeverityThreshold(value)
			require.ErrorIs(t, err, errInvalidSeverityThreshold)
		})
	}
}
