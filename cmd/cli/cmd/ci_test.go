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
			name:     "sast envelope",
			body:     `{"version":"1","findings":[{"id":"f1"}],"numItems":1,"nextToken":""}`,
			expected: 1,
		},
		{
			name:     "sca dependencies envelope",
			body:     `{"version":"1","findings":[{"id":"f1"},{"id":"f2"}],"numItems":2,"nextToken":"abc"}`,
			expected: 2,
		},
		{
			name:     "sca containers envelope",
			body:     `{"findings":[{"id":"f1"}],"numItems":1,"nextToken":""}`,
			expected: 1,
		},
		{
			name:     "secrets envelope",
			body:     `{"findings":[],"numItems":0,"nextToken":""}`,
			expected: 0,
		},
		{
			name:     "pentest envelope",
			body:     `{"findings":[{"id":"f1"},{"id":"f2"},{"id":"f3"}],"numItems":3,"nextToken":""}`,
			expected: 3,
		},
		{
			name:     "bughunt envelope omits numItems",
			body:     `{"findings":[{"id":"f1"},{"id":"f2"}]}`,
			expected: 2,
		},
		{
			name:     "cspm envelope omits empty nextToken",
			body:     `{"findings":[{"id":"f1"}],"numItems":1,"version":"1"}`,
			expected: 1,
		},
		{
			name:     "nil findings slice serialises as null",
			body:     `{"findings":null,"numItems":0,"nextToken":""}`,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := countFindings(tt.body)
			require.NoError(t, err)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestCountFindingsRejectsUnknownEnvelopes(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "invalid json", body: `not json`},
		{name: "empty object", body: `{}`},
		{name: "bare array", body: `[{"id":"f1"}]`},
		{name: "items envelope", body: `{"items":[{"id":"f1"}]}`},
		{name: "total envelope", body: `{"total":42}`},
		{name: "findings is not an array", body: `{"findings":{"id":"f1"}}`},
		{name: "empty body", body: ``},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, err := countFindings(tt.body)
			require.ErrorIs(t, err, errUnreadableFindings)
			require.Zero(t, count)
		})
	}
}
