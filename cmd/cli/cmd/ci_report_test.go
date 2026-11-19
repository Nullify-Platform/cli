package cmd

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCIReportReadsEveryPageAtThePageCap(t *testing.T) {
	useCIEnv(t)
	api := serveScannerAPI(t, func(r *http.Request) (int, string) {
		query := r.URL.Query()
		if r.URL.Path != "/sast/findings" || query.Get("severity") != "CRITICAL" {
			return emptyFindings(r)
		}
		switch query.Get("nextToken") {
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
	require.Contains(t, requests, "/sast/findings?isResolved=false&limit=100&nextToken=p2&repository=org%2Frepo&severity=CRITICAL")
	for _, request := range requests {
		require.Contains(t, request, "limit=100", "every request asks for the server's page cap")
	}
}
