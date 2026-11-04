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

func TestCountFindings(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected int
	}{
		{
			name:     "empty array",
			body:     `[]`,
			expected: 0,
		},
		{
			name:     "array with items",
			body:     `[{"id": 1}, {"id": 2}, {"id": 3}]`,
			expected: 3,
		},
		{
			name:     "object with items array",
			body:     `{"items": [{"id": 1}]}`,
			expected: 1,
		},
		{
			name:     "object with total field",
			body:     `{"total": 42}`,
			expected: 42,
		},
		{
			name:     "invalid json",
			body:     `not json`,
			expected: 0,
		},
		{
			name:     "empty object",
			body:     `{}`,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := countFindings(tt.body)
			require.Equal(t, tt.expected, result)
		})
	}
}
