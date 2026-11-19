package cmd

import (
	"encoding/json"
	"net/http"
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

func TestScannerQueryParamsMatchEndpointFilters(t *testing.T) {
	scope := repositoryScope{id: "42", source: "--repository-id", providerParams: []string{"githubRepositoryId", "42"}}
	tests := []struct {
		scanner  string
		expected []string
	}{
		{scanner: "sast", expected: []string{"severity", "CRITICAL", "isResolved", "false", "githubRepositoryId", "42", "repositoryIds", "42"}},
		{scanner: "cspm", expected: []string{"severity", "CRITICAL", "status", "open"}},
		{scanner: "sca_dependencies", expected: []string{"isResolved", "false", "githubRepositoryId", "42"}},
		{scanner: "sca_containers", expected: []string{"isResolved", "false", "githubRepositoryId", "42"}},
		{scanner: "secrets", expected: []string{"isResolved", "false", "githubRepositoryId", "42"}},
		{scanner: "pentest", expected: []string{"isResolved", "false"}},
		{scanner: "bughunt", expected: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.scanner, func(t *testing.T) {
			ep := scannerByName(t, tt.scanner)
			severities := scannerSeverities(ep, []string{"critical", "high"})
			require.Equal(t, tt.expected, scannerQueryParams(ep, severities[0], scope))
		})
	}
}

func TestScannerSeveritiesCollapseWithoutServerSideFilter(t *testing.T) {
	byName := map[string]scannerEndpoint{}
	for _, ep := range allScannerEndpoints() {
		byName[ep.name] = ep
	}

	threshold := []string{"critical", "high"}

	withUnknown := []string{"critical", "high", "unknown"}
	require.Equal(t, withUnknown, scannerSeverities(byName["sast"], threshold))
	require.Equal(t, withUnknown, scannerSeverities(byName["cspm"], threshold))
	require.Equal(t, []string{"critical", "high"}, threshold, "the caller's slice is not changed")
	require.Equal(t, []string{""}, scannerSeverities(byName["secrets"], threshold))
	require.Equal(t, []string{""}, scannerSeverities(byName["bughunt"], threshold))

	require.Equal(t,
		"FAIL: secrets has open findings (its findings carry no severity, so every open one counts)",
		gateFailLine(gateCheck{ep: byName["secrets"]}, severityHigh),
	)
	require.Equal(t,
		"FAIL: sca_dependencies has open findings at or above high severity",
		gateFailLine(gateCheck{ep: byName["sca_dependencies"]}, severityHigh),
	)
	require.Equal(t,
		"FAIL: sast has open critical findings",
		gateFailLine(gateCheck{ep: byName["sast"], severity: "critical"}, severityHigh),
	)
}

func TestCIGateResponseValidation(t *testing.T) {
	tests := []struct {
		name     string
		scanner  string
		body     string
		wantExit int
	}{
		{"missing findings", "sast", `{}`, ExitNetworkError},
		{"malformed findings", "sast", `{"findings":{},"numItems":0}`, ExitNetworkError},
		{"legacy zero count", "pentest", `{"findings":[{"id":"f1"}],"numItems":0}`, ExitFindings},
		{"negative count", "sast", `{"findings":[],"numItems":-1}`, ExitNetworkError},
		{"finding", "sast", `{"findings":[{"id":"f1"}],"numItems":1}`, ExitFindings},
		{"clean", "sast", `{"findings":[],"numItems":0}`, ExitSuccess},
		{"nil page", "sast", `{"findings":null,"numItems":0}`, ExitSuccess},
		{"no count", "bughunt", `{"findings":[{"id":"f1"}]}`, ExitFindings},
		{"cspm open filter", "cspm", `{"findings":[],"numItems":0}`, ExitSuccess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCIEnv(t)
			api := serveScannerAPI(t, func(req *http.Request) (int, string) {
				if tt.scanner == "cspm" {
					query := req.URL.Query()
					severity := query.Get("severity")
					if query.Get("status") != "open" || (severity != "CRITICAL" && severity != "UNKNOWN") {
						t.Errorf("unexpected CSPM filters: %s", req.URL.RawQuery)
					}
				}
				return http.StatusOK, tt.body
			})

			_, err := runCI(t, ciGateCmd, map[string]string{
				"severity-threshold": "critical",
				"type":               tt.scanner,
				"repository-id":      "42",
			})

			require.Equal(t, tt.wantExit, ExitCodeForError(err))
			wantRequests := 1
			if scannerByName(t, tt.scanner).supportsSeverity {
				wantRequests = 2 // CRITICAL and UNKNOWN
			}
			require.Len(t, api.requests(), wantRequests)
		})
	}
}

func TestCIReportPreservesPentestFindingsWithZeroCount(t *testing.T) {
	useCIEnv(t)
	serveScannerAPI(t, func(req *http.Request) (int, string) {
		if req.URL.Path == "/dast/pentest/findings" {
			return http.StatusOK, `{"findings":[{"id":"pentest-1","title":"Critical pentest finding","severity":"CRITICAL"}],"groups":null,"numItems":0,"nextToken":""}`
		}
		return emptyFindings(req)
	})

	for _, format := range []string{"markdown", "sarif"} {
		t.Run(format, func(t *testing.T) {
			report, err := runCI(t, ciReportCmd, map[string]string{"repository-id": "42", "format": format})
			require.NoError(t, err)
			if format == "markdown" {
				require.Contains(t, report, "| pentest | critical | 1 |")
				return
			}

			var sarif struct {
				Runs []struct {
					Results []struct {
						Level   string `json:"level"`
						Message struct {
							Text string `json:"text"`
						} `json:"message"`
					} `json:"results"`
				} `json:"runs"`
			}
			require.NoError(t, json.Unmarshal([]byte(report), &sarif))
			require.Len(t, sarif.Runs, 1)
			require.Len(t, sarif.Runs[0].Results, 1)
			for _, result := range sarif.Runs[0].Results {
				require.Equal(t, "error", result.Level)
				require.Equal(t, "Critical pentest finding", result.Message.Text)
			}
		})
	}
}
