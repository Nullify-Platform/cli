package cmd

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func gateRequests(severities ...string) []string {
	want := []string{
		"/sca/dependencies/findings?isResolved=false&limit=100&repository=acme%2Fapp",
		"/sca/containers/findings?isResolved=false&limit=100&repository=acme%2Fapp",
		"/secrets/findings?isResolved=false&limit=100&repository=acme%2Fapp",
		"/dast/pentest/findings?isResolved=false&limit=100&repository=acme%2Fapp",
		"/dast/bughunt/findings?limit=100&repository=acme%2Fapp",
	}
	for _, severity := range severities {
		want = append(want,
			"/sast/findings?isResolved=false&limit=100&repository=acme%2Fapp&severity="+strings.ToUpper(severity),
			"/cspm/findings?limit=100&repository=acme%2Fapp&severity="+strings.ToUpper(severity)+"&status=open",
		)
	}
	slices.Sort(want)
	return want
}

func TestCIGateRequestsAndExitCodes(t *testing.T) {
	tests := []struct {
		name      string
		threshold string
		findType  string
		status    int
		body      string
		exit      int
		requests  []string
	}{
		{name: "the default set", threshold: "high", status: http.StatusOK, body: `{"findings":[]}`, exit: ExitSuccess, requests: gateRequests("critical", "high")},
		{name: "every severity", threshold: "low", status: http.StatusOK, body: `{"findings":[]}`, exit: ExitSuccess, requests: gateRequests("critical", "high", "low", "medium")},
		{name: "a list route type", threshold: "critical", findType: "cspm", status: http.StatusOK, body: `{"findings":[]}`, exit: ExitSuccess, requests: []string{"/cspm/findings?limit=100&repository=acme%2Fapp&severity=CRITICAL&status=open"}},
		{name: "scpm is not a gate type", threshold: "critical", findType: "scpm", status: http.StatusOK, body: `{"findings":[]}`, exit: ExitSuccess, requests: gateRequests("critical")},
		{name: "sensitive data is not a gate type", threshold: "critical", findType: "secrets_sensitive_data", status: http.StatusOK, body: `{"findings":[]}`, exit: ExitSuccess, requests: gateRequests("critical")},
		{name: "a monorepo name is not a gate type", threshold: "critical", findType: "dast_pentest", status: http.StatusOK, body: `{"findings":[]}`, exit: ExitSuccess, requests: gateRequests("critical")},
		{name: "findings fail the gate", threshold: "critical", findType: "sast", status: http.StatusOK, body: `{"findings":[{"id":"f1","severity":"CRITICAL"},{"id":"f2","severity":"CRITICAL"}]}`, exit: ExitFindings, requests: []string{"/sast/findings?isResolved=false&limit=100&repository=acme%2Fapp&severity=CRITICAL"}},
		{name: "a total without findings fails closed", threshold: "critical", findType: "sast", status: http.StatusOK, body: `{"total":0}`, exit: ExitNetworkError, requests: []string{"/sast/findings?isResolved=false&limit=100&repository=acme%2Fapp&severity=CRITICAL"}},
		{name: "a failed request exits 3", threshold: "critical", findType: "sast", status: http.StatusBadRequest, body: `{}`, exit: ExitNetworkError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCIEnv(t)
			api := serveScannerAPI(t, func(*http.Request) (int, string) { return tt.status, tt.body })

			_, err := runCI(t, ciGateCmd, map[string]string{
				"severity-threshold": tt.threshold,
				"type":               tt.findType,
				"repo":               "acme/app",
			})

			require.Equal(t, tt.exit, ExitCodeForError(err))
			if tt.requests != nil {
				require.Equal(t, tt.requests, api.requests())
			}
		})
	}
}

func TestCIGateAppliesTheThresholdToEveryScanner(t *testing.T) {
	tests := []struct {
		name      string
		findType  string
		threshold string
		finding   string
		exit      int
	}{
		{"a low dependency finding passes a critical gate", "sca_dependencies", "critical", `{"id":"d1","vulnerabilitiesMaxSeverity":"LOW"}`, ExitSuccess},
		{"a critical dependency finding fails a critical gate", "sca_dependencies", "critical", `{"id":"d1","vulnerabilitiesMaxSeverity":"CRITICAL"}`, ExitFindings},
		{"a medium container finding passes a high gate", "sca_containers", "high", `{"id":"c1","vulnerabilitiesMaxSeverity":"MEDIUM"}`, ExitSuccess},
		{"a high container finding fails a high gate", "sca_containers", "high", `{"id":"c1","vulnerabilitiesMaxSeverity":"HIGH"}`, ExitFindings},
		{"a low pentest finding passes a high gate", "pentest", "high", `{"id":"p1","effectiveSeverity":"LOW"}`, ExitSuccess},
		{"a high pentest finding fails a high gate", "pentest", "high", `{"id":"p1","effectiveSeverity":"HIGH"}`, ExitFindings},
		{"a bughunt override below the gate passes", "bughunt", "high", `{"id":"b1","severity":"CRITICAL","severityOverride":"LOW"}`, ExitSuccess},
		{"a critical bughunt finding fails a critical gate", "bughunt", "critical", `{"id":"b1","severity":"CRITICAL"}`, ExitFindings},
		{"an informational finding passes a low gate", "sca_dependencies", "low", `{"id":"d1","vulnerabilitiesMaxSeverity":"INFORMATIONAL"}`, ExitSuccess},
		{"a finding without a severity fails closed", "sca_containers", "critical", `{"id":"c1"}`, ExitFindings},
		{"a secret has no severity and fails any gate", "secrets", "critical", `{"id":"s1","priorityLabel":"LOW"}`, ExitFindings},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCIEnv(t)
			serveScannerAPI(t, func(*http.Request) (int, string) {
				return http.StatusOK, `{"findings":[` + tt.finding + `]}`
			})

			_, err := runCI(t, ciGateCmd, map[string]string{
				"severity-threshold": tt.threshold,
				"type":               tt.findType,
				"repo":               "acme/app",
			})

			require.Equal(t, tt.exit, ExitCodeForError(err))
		})
	}
}

func TestCIGateReadsLaterPages(t *testing.T) {
	useCIEnv(t)
	api := serveScannerAPI(t, func(r *http.Request) (int, string) {
		if r.URL.Query().Get("nextToken") == "" {
			return http.StatusOK, `{"findings":[{"id":"d1","vulnerabilitiesMaxSeverity":"LOW"}],"numItems":1,"nextToken":"p2"}`
		}
		return http.StatusOK, `{"findings":[{"id":"d2","vulnerabilitiesMaxSeverity":"CRITICAL"}],"numItems":1,"nextToken":""}`
	})

	out, err := runCI(t, ciGateCmd, map[string]string{
		"severity-threshold": "critical",
		"type":               "sca_dependencies",
		"repo":               "acme/app",
	})

	require.Equal(t, ExitFindings, ExitCodeForError(err))
	require.Contains(t, out, "FAIL: sca_dependencies has open findings at or above critical severity")
	require.Len(t, api.requests(), 2)
}
