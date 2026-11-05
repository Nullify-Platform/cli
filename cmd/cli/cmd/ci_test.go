package cmd

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"

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

func TestScannerQueryParamsMatchEndpointFilters(t *testing.T) {
	byName := map[string]scannerEndpoint{}
	for _, ep := range allScannerEndpoints() {
		byName[ep.name] = ep
	}

	tests := []struct {
		scanner  string
		expected []string
	}{
		{
			scanner:  "sast",
			expected: []string{"limit", "1", "severity", "CRITICAL", "isResolved", "false", "repository", "org/repo"},
		},
		{
			scanner:  "cspm",
			expected: []string{"limit", "1", "severity", "CRITICAL", "status", "open", "repository", "org/repo"},
		},
		{
			scanner:  "sca_dependencies",
			expected: []string{"limit", "1", "isResolved", "false", "repository", "org/repo"},
		},
		{
			scanner:  "sca_containers",
			expected: []string{"limit", "1", "isResolved", "false", "repository", "org/repo"},
		},
		{
			scanner:  "secrets",
			expected: []string{"limit", "1", "isResolved", "false", "repository", "org/repo"},
		},
		{
			scanner:  "pentest",
			expected: []string{"limit", "1", "isResolved", "false", "repository", "org/repo"},
		},
		{
			scanner:  "bughunt",
			expected: []string{"limit", "1", "repository", "org/repo"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.scanner, func(t *testing.T) {
			ep, ok := byName[tt.scanner]
			require.True(t, ok)

			severities := scannerSeverities(ep, []string{"critical", "high"})
			params := scannerQueryParams(ep, severities[0], "org/repo", "1")
			require.Equal(t, tt.expected, params)
		})
	}
}

func TestScannerSeveritiesCollapseWithoutServerSideFilter(t *testing.T) {
	byName := map[string]scannerEndpoint{}
	for _, ep := range allScannerEndpoints() {
		byName[ep.name] = ep
	}

	threshold := []string{"critical", "high"}

	require.Equal(t, threshold, scannerSeverities(byName["sast"], threshold))
	require.Equal(t, threshold, scannerSeverities(byName["cspm"], threshold))
	require.Equal(t, []string{""}, scannerSeverities(byName["secrets"], threshold))
	require.Equal(t, []string{""}, scannerSeverities(byName["bughunt"], threshold))

	require.Equal(t,
		"FAIL: secrets has open findings (no server-side severity filter, threshold not applied)",
		gateFailLine(byName["secrets"], ""),
	)
	require.Equal(t, "FAIL: sast has open critical findings", gateFailLine(byName["sast"], "critical"))
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
		{name: "object with zero count", body: `{"findings":{},"numItems":0}`},
		{name: "boolean with zero count", body: `{"findings":false,"numItems":0}`},
		{name: "negative count", body: `{"findings":[],"numItems":-1}`},
		{name: "understated count", body: `{"findings":[{"id":"f1"}],"numItems":0}`},
		{name: "overstated count", body: `{"findings":[],"numItems":1}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, err := countFindings(tt.body)
			require.ErrorIs(t, err, errUnreadableFindings)
			require.Zero(t, count)
		})
	}
}

func TestCIGateResponseValidation(t *testing.T) {
	t.Setenv("NULLIFY_HOST", "review.nullify.ai")
	t.Setenv("NULLIFY_TOKEN", "synthetic-token")
	originalHost, originalToken, originalGithub := host, nullifyToken, githubToken
	host, nullifyToken, githubToken = "review.nullify.ai", "synthetic-token", ""
	t.Cleanup(func() {
		host, nullifyToken, githubToken = originalHost, originalToken, originalGithub
	})

	tests := []struct {
		name     string
		scanner  string
		body     string
		wantExit int
	}{
		{"missing findings", "sast", `{}`, ExitNetworkError},
		{"malformed findings", "sast", `{"findings":{},"numItems":0}`, ExitNetworkError},
		{"hidden finding", "sast", `{"findings":[{"id":"f1"}],"numItems":0}`, ExitNetworkError},
		{"negative count", "sast", `{"findings":[],"numItems":-1}`, ExitNetworkError},
		{"finding", "sast", `{"findings":[{"id":"f1"}],"numItems":1}`, ExitFindings},
		{"clean", "sast", `{"findings":[],"numItems":0}`, ExitSuccess},
		{"nil page", "sast", `{"findings":null,"numItems":0}`, ExitSuccess},
		{"no count", "bughunt", `{"findings":[{"id":"f1"}]}`, ExitFindings},
		{"cspm open filter", "cspm", `{"findings":[],"numItems":0}`, ExitSuccess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalTransport := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = originalTransport })
			var calls atomic.Int64
			http.DefaultTransport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				calls.Add(1)
				if tt.scanner == "cspm" {
					query := req.URL.Query()
					if query.Get("status") != "open" || query.Get("severity") != "CRITICAL" {
						t.Errorf("unexpected CSPM filters: %s", req.URL.RawQuery)
					}
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(tt.body)),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			})

			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			cmd.Flags().String("severity-threshold", "critical", "")
			cmd.Flags().String("type", tt.scanner, "")
			cmd.Flags().String("repo", "org/repo", "")
			err := ciGateCmd.RunE(cmd, nil)

			require.Equal(t, tt.wantExit, ExitCodeForError(err))
			require.Equal(t, int64(1), calls.Load())
		})
	}
}
