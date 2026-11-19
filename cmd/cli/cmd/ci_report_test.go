package cmd

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCIReportReadsEveryPageAtThePageCap(t *testing.T) {
	useCIEnv(t)
	api := serveScannerAPI(t, func(r *http.Request) (int, string) {
		if r.URL.Path != "/sast/findings" {
			return emptyFindings(r)
		}
		switch r.URL.Query().Get("nextToken") {
		case "":
			return http.StatusOK, `{"findings":[{"id":"f1","severity":"CRITICAL"},{"id":"f2","severity":"CRITICAL"}],"numItems":2,"nextToken":"p2"}`
		case "p2":
			return http.StatusOK, `{"findings":[{"id":"f3","severity":"CRITICAL"}],"numItems":1,"nextToken":""}`
		default:
			return http.StatusNotFound, `{"error":"no such page"}`
		}
	})

	out, err := runCI(t, ciReportCmd, map[string]string{"repo": "org/repo"})

	require.NoError(t, err)
	require.Contains(t, out, "| sast | critical | 3 |")
	requests := api.requests()
	require.Contains(t, requests, "/sast/findings?isResolved=false&limit=100&nextToken=p2&repository=org%2Frepo")
	for _, request := range requests {
		require.Contains(t, request, "limit=100", "every request asks for the server's page cap")
	}
}

func TestCIReportCountsEachFindingOnceUnderItsOwnSeverity(t *testing.T) {
	useCIEnv(t)
	api := serveScannerAPI(t, func(r *http.Request) (int, string) {
		switch r.URL.Path {
		case "/sca/dependencies/findings":
			return http.StatusOK, `{"findings":[
				{"id":"d1","aiTitle":"Critical dependency","vulnerabilitiesMaxSeverity":"CRITICAL"},
				{"id":"d2","aiTitle":"Low dependency","vulnerabilitiesMaxSeverity":"LOW"},
				{"id":"d3","aiTitle":"Another low dependency","vulnerabilitiesMaxSeverity":"LOW"}
			],"numItems":3}`
		case "/secrets/findings":
			return http.StatusOK, `{"findings":[{"id":"s1","aiTitle":"Leaked key"}],"numItems":1}`
		default:
			return emptyFindings(r)
		}
	})

	markdown, err := runCI(t, ciReportCmd, map[string]string{"repo": "org/repo"})
	require.NoError(t, err)
	require.Contains(t, markdown, "| sca_dependencies | critical | 1 |")
	require.Contains(t, markdown, "| sca_dependencies | low | 2 |")
	require.Contains(t, markdown, "| secrets | unknown | 1 |")
	require.NotContains(t, markdown, "| sca_dependencies | high |")
	require.Len(t, api.requests(), len(allScannerEndpoints()), "one request per scanner")

	sarif, err := runCI(t, ciReportCmd, map[string]string{"repo": "org/repo", "format": "sarif"})
	require.NoError(t, err)
	var document struct {
		Runs []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal([]byte(sarif), &document))
	require.Len(t, document.Runs, 1)
	require.Len(t, document.Runs[0].Results, 4, "each finding appears once")
}
