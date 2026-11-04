package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSeveritiesAboveThreshold(t *testing.T) {
	tests := []struct {
		threshold string
		expected  []string
	}{
		{"critical", []string{"critical"}},
		{"high", []string{"critical", "high"}},
		{"medium", []string{"critical", "high", "medium"}},
		{"low", []string{"critical", "high", "medium", "low"}},
		{"unknown", []string{"critical", "high"}},
	}

	for _, tt := range tests {
		t.Run(tt.threshold, func(t *testing.T) {
			result := severitiesAboveThreshold(tt.threshold)
			require.Equal(t, tt.expected, result)
		})
	}
}
