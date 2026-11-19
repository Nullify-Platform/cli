package mcp

import (
	"net/url"
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
)

func TestListScanRunsSendsWhatTheHandlersRequire(t *testing.T) {
	tests := []struct {
		name    string
		args    map[string]any
		path    string
		query   url.Values
		isError bool
	}{
		{
			name:  "sast sends the repository",
			args:  map[string]any{"type": "sast", "repository_id": "r1", "limit": 5},
			path:  "/sast/scan-runs",
			query: url.Values{"repositoryId": {"r1"}, "limit": {"5"}},
		},
		{
			name:  "secrets sends the repository",
			args:  map[string]any{"type": "secrets", "repository_id": "r1"},
			path:  "/secrets/scan-runs",
			query: url.Values{"repositoryId": {"r1"}},
		},
		{
			name:  "sca sends the repository and the scan type",
			args:  map[string]any{"type": "sca", "repository_id": "r1", "scan_type": "sca_containers"},
			path:  "/sca/scan-runs",
			query: url.Values{"repositoryId": {"r1"}, "scanType": {"sca_containers"}},
		},
		{
			name:  "scpm sends the repository",
			args:  map[string]any{"type": "scpm", "repository_id": "r1"},
			path:  "/scpm/scan-runs",
			query: url.Values{"repositoryId": {"r1"}},
		},
		{
			name:  "scpm lists the whole tenant without a repository",
			args:  map[string]any{"type": "scpm"},
			path:  "/scpm/scan-runs",
			query: url.Values{},
		},
		{name: "sca without a scan type sends nothing", args: map[string]any{"type": "sca", "repository_id": "r1"}, isError: true},
		{name: "sca with an unknown scan type sends nothing", args: map[string]any{"type": "sca", "repository_id": "r1", "scan_type": "sca"}, isError: true},
		{name: "a scan type on another scanner sends nothing", args: map[string]any{"type": "sast", "repository_id": "r1", "scan_type": "sca_containers"}, isError: true},
		{name: "sast without a repository sends nothing", args: map[string]any{"type": "sast"}, isError: true},
		{name: "an unknown scanner sends nothing", args: map[string]any{"type": "dast", "repository_id": "r1"}, isError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{}
			s := server.NewMCPServer("test", "1", server.WithToolCapabilities(true))
			registerScanTools(s, testClient(ft))

			result := callFindingTool(t, s, "nullify_list_scan_runs", tt.args)

			require.Equal(t, tt.isError, result.IsError, result.Content)
			if tt.isError {
				require.Empty(t, ft.requests)
				return
			}
			require.Len(t, ft.requests, 1)
			require.Equal(t, tt.path, ft.requests[0].path)
			require.Equal(t, tt.query, ft.queries[0])
		})
	}
}

func TestEveryAdvertisedScannerHasALister(t *testing.T) {
	require.Len(t, scanRunMethods, len(scanRunScanners))
	for _, scanner := range scanRunScanners {
		require.Contains(t, scanRunMethods, scanner)
	}
}
