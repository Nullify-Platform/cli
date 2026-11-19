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
		"/sca/dependencies/findings?githubRepositoryId=42&isResolved=false&limit=100",
		"/sca/containers/findings?githubRepositoryId=42&isResolved=false&limit=100",
		"/secrets/findings?githubRepositoryId=42&isResolved=false&limit=100",
		"/dast/pentest/findings?isResolved=false&limit=100",
		"/dast/bughunt/findings?limit=100",
	}
	for _, severity := range append(severities, "unknown") {
		want = append(want,
			"/sast/findings?githubRepositoryId=42&isResolved=false&limit=100&repositoryIds=42&severity="+strings.ToUpper(severity),
			"/cspm/findings?limit=100&severity="+strings.ToUpper(severity)+"&status=open",
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
		{name: "a list route type", threshold: "critical", findType: "cspm", status: http.StatusOK, body: `{"findings":[]}`, exit: ExitSuccess, requests: []string{"/cspm/findings?limit=100&severity=CRITICAL&status=open", "/cspm/findings?limit=100&severity=UNKNOWN&status=open"}},
		{name: "scpm is not a gate type", threshold: "critical", findType: "scpm", status: http.StatusOK, body: `{"findings":[]}`, exit: ExitSuccess, requests: gateRequests("critical")},
		{name: "sensitive data is not a gate type", threshold: "critical", findType: "secrets_sensitive_data", status: http.StatusOK, body: `{"findings":[]}`, exit: ExitSuccess, requests: gateRequests("critical")},
		{name: "a monorepo name is not a gate type", threshold: "critical", findType: "dast_pentest", status: http.StatusOK, body: `{"findings":[]}`, exit: ExitSuccess, requests: gateRequests("critical")},
		{name: "findings fail the gate", threshold: "critical", findType: "sast", status: http.StatusOK, body: `{"findings":[{"id":"f1","severity":"CRITICAL"},{"id":"f2","severity":"CRITICAL"}]}`, exit: ExitFindings, requests: []string{"/sast/findings?githubRepositoryId=42&isResolved=false&limit=100&repositoryIds=42&severity=CRITICAL", "/sast/findings?githubRepositoryId=42&isResolved=false&limit=100&repositoryIds=42&severity=UNKNOWN"}},
		{name: "a total without findings fails closed", threshold: "critical", findType: "sast", status: http.StatusOK, body: `{"total":0}`, exit: ExitNetworkError, requests: []string{"/sast/findings?githubRepositoryId=42&isResolved=false&limit=100&repositoryIds=42&severity=CRITICAL", "/sast/findings?githubRepositoryId=42&isResolved=false&limit=100&repositoryIds=42&severity=UNKNOWN"}},
		{name: "a failed request exits 3", threshold: "critical", findType: "sast", status: http.StatusBadRequest, body: `{}`, exit: ExitNetworkError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCIEnv(t)
			api := serveScannerAPI(t, func(*http.Request) (int, string) { return tt.status, tt.body })

			_, err := runCI(t, ciGateCmd, map[string]string{
				"severity-threshold": tt.threshold,
				"type":               tt.findType,
				"repository-id":      "42",
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
				"repository-id":      "42",
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
		"repository-id":      "42",
	})

	require.Equal(t, ExitFindings, ExitCodeForError(err))
	require.Contains(t, out, "FAIL: sca_dependencies has open findings at or above critical severity")
	require.Len(t, api.requests(), 2)
}

func TestCIGateCountsOnlyOpenBughuntFindings(t *testing.T) {
	tests := []struct {
		name    string
		finding string
		exit    int
	}{
		{"an open finding fails the gate", `{"id":"b1","severity":"CRITICAL","isLatest":true}`, ExitFindings},
		{"an allowlisted finding passes", `{"id":"b1","severity":"CRITICAL","isAllowlisted":true}`, ExitSuccess},
		{"an archived finding passes", `{"id":"b1","severity":"CRITICAL","isArchived":true}`, ExitSuccess},
		{"a false positive passes", `{"id":"b1","severity":"CRITICAL","isFalsePositive":true}`, ExitSuccess},
		{"a fixed finding passes", `{"id":"b1","severity":"CRITICAL","isFixed":true}`, ExitSuccess},
		{"a superseded finding passes", `{"id":"b1","severity":"CRITICAL","isLatest":false}`, ExitSuccess},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCIEnv(t)
			serveScannerAPI(t, func(*http.Request) (int, string) {
				return http.StatusOK, `{"findings":[` + tt.finding + `]}`
			})

			_, err := runCI(t, ciGateCmd, map[string]string{
				"severity-threshold": "high",
				"type":               "bughunt",
				"repository-id":      "42",
			})

			require.Equal(t, tt.exit, ExitCodeForError(err))
		})
	}
}

func TestCIGateCountsOnlyTheScopedRepository(t *testing.T) {
	tests := []struct {
		name     string
		findings string
		exit     int
	}{
		{"another repository's finding passes", `{"id":"d1","repositoryId":"99","vulnerabilitiesMaxSeverity":"CRITICAL"}`, ExitSuccess},
		{"this repository's finding fails", `{"id":"d1","repositoryId":"42","vulnerabilitiesMaxSeverity":"CRITICAL"}`, ExitFindings},
		{"a finding without a repository id fails closed", `{"id":"d1","vulnerabilitiesMaxSeverity":"CRITICAL"}`, ExitFindings},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCIEnv(t)
			serveScannerAPI(t, func(*http.Request) (int, string) {
				return http.StatusOK, `{"findings":[` + tt.findings + `]}`
			})

			_, err := runCI(t, ciGateCmd, map[string]string{"type": "sca_dependencies", "repository-id": "42"})

			require.Equal(t, tt.exit, ExitCodeForError(err))
		})
	}
}

func TestCIGateResolvesItsRepositoryScope(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		flags    map[string]string
		exit     int
		requests []string
	}{
		{
			name:     "github actions names the repository",
			env:      map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY_ID": "7"},
			exit:     ExitSuccess,
			requests: []string{"/secrets/findings?githubRepositoryId=7&isResolved=false&limit=100"},
		},
		{
			name:     "bitbucket pipelines names the repository",
			env:      map[string]string{"BITBUCKET_BUILD_NUMBER": "3", "BITBUCKET_REPO_UUID": "{abc-123}"},
			exit:     ExitSuccess,
			requests: []string{"/secrets/findings?bitbucketRepositoryId=abc-123&isResolved=false&limit=100"},
		},
		{
			name:     "every repository on request",
			flags:    map[string]string{"all-repositories": "true"},
			exit:     ExitSuccess,
			requests: []string{"/secrets/findings?isResolved=false&limit=100"},
		},
		{
			name: "no repository is a usage error",
			exit: ExitUsageError,
		},
		{
			name:  "the retired --repo flag names no repository",
			flags: map[string]string{"repo": "acme/app"},
			exit:  ExitUsageError,
		},
		{
			name:  "an id and every repository conflict",
			flags: map[string]string{"repository-id": "42", "all-repositories": "true"},
			exit:  ExitUsageError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCIEnv(t)
			for name, value := range tt.env {
				t.Setenv(name, value)
			}
			api := serveScannerAPI(t, emptyFindings)
			flags := map[string]string{"type": "secrets"}
			for name, value := range tt.flags {
				flags[name] = value
			}

			_, err := runCI(t, ciGateCmd, flags)

			require.Equal(t, tt.exit, ExitCodeForError(err))
			require.Equal(t, tt.requests, nilIfEmpty(api.requests()))
		})
	}
}

func nilIfEmpty(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return values
}

func TestCIGateNamesAListItCouldNotFinish(t *testing.T) {
	useCIEnv(t)
	serveScannerAPI(t, func(*http.Request) (int, string) {
		return http.StatusOK, `{"findings":[],"numItems":0,"nextToken":"again"}`
	})

	var err error
	stderr := captureStderr(t, func() {
		_, err = runCI(t, ciGateCmd, map[string]string{"type": "secrets", "repository-id": "42"})
	})

	require.Equal(t, ExitNetworkError, ExitCodeForError(err))
	require.Contains(t, stderr, "Error: could not read all of secrets: the finding list did not end within 100 pages")
}

func TestCIGateCountsServerFilteredFindingsOfUnknownSeverity(t *testing.T) {
	for _, scanner := range []string{"sast", "cspm"} {
		t.Run(scanner, func(t *testing.T) {
			useCIEnv(t)
			serveScannerAPI(t, func(r *http.Request) (int, string) {
				if r.URL.Query().Get("severity") == "UNKNOWN" {
					return http.StatusOK, `{"findings":[{"id":"u1","severity":"UNKNOWN"}]}`
				}
				return emptyFindings(r)
			})

			out, err := runCI(t, ciGateCmd, map[string]string{
				"severity-threshold": "critical",
				"type":               scanner,
				"repository-id":      "42",
			})

			require.Equal(t, ExitFindings, ExitCodeForError(err))
			require.Contains(t, out, "FAIL: "+scanner+" has open findings of unknown severity")
		})
	}
}

func TestCIGateWarnsWhenTheServerDidNotNarrowToTheRepository(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		flags    map[string]string
		wantWarn bool
	}{
		{"a github id the server ignored", nil, map[string]string{"repository-id": "42"}, true},
		{"gitlab, which the server cannot narrow", map[string]string{"GITLAB_CI": "true", "CI_PROJECT_ID": "42"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCIEnv(t)
			for name, value := range tt.env {
				t.Setenv(name, value)
			}
			serveScannerAPI(t, func(*http.Request) (int, string) {
				return http.StatusOK, `{"findings":[{"id":"s1","repositoryId":"99"},{"id":"s2","repositoryId":"98"}]}`
			})
			flags := map[string]string{"type": "secrets"}
			for name, value := range tt.flags {
				flags[name] = value
			}

			var err error
			stderr := captureStderr(t, func() { _, err = runCI(t, ciGateCmd, flags) })

			require.Equal(t, ExitSuccess, ExitCodeForError(err))
			warning := "Warning: secrets returned 2 finding(s) of other repositories"
			if tt.wantWarn {
				require.Contains(t, stderr, warning)
			} else {
				require.NotContains(t, stderr, warning)
			}
		})
	}
}
