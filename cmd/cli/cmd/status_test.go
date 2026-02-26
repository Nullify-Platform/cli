package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSummarizeFindingsResponse(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "array response",
			body:     `[{"id":1},{"id":2}]`,
			expected: "2 findings returned",
		},
		{
			name:     "object with items",
			body:     `{"items":[{"id":1}]}`,
			expected: "1 findings returned",
		},
		{
			name:     "object with total",
			body:     `{"total":99}`,
			expected: "99 total findings",
		},
		{
			name:     "empty object",
			body:     `{}`,
			expected: "data available",
		},
		{
			name:     "invalid json",
			body:     `nope`,
			expected: "data available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := summarizeFindingsResponse(tt.body)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestAllScannerEndpoints(t *testing.T) {
	endpoints := allScannerEndpoints()
	require.Len(t, endpoints, 7)

	names := make([]string, len(endpoints))
	for i, ep := range endpoints {
		names[i] = ep.name
	}
	require.Contains(t, names, "sast")
	require.Contains(t, names, "pentest")
	require.Contains(t, names, "bughunt")
}

func TestFilterEndpointsByType(t *testing.T) {
	endpoints := allScannerEndpoints()

	filtered := filterEndpointsByType(endpoints, "sast")
	require.Len(t, filtered, 1)
	require.Equal(t, "sast", filtered[0].name)

	noMatch := filterEndpointsByType(endpoints, "nonexistent")
	require.Nil(t, noMatch)
}
