package cmd

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListScanRunsRequest(t *testing.T) {
	tests := []struct {
		scanType     string
		wantPath     string
		wantScanType string
	}{
		{scanType: "sca", wantPath: "/sca/scan-runs", wantScanType: "sca_dependencies"},
		{scanType: "sca_dependencies", wantPath: "/sca/scan-runs", wantScanType: "sca_dependencies"},
		{scanType: "sca_containers", wantPath: "/sca/scan-runs", wantScanType: "sca_containers"},
		{scanType: "sast", wantPath: "/sast/scan-runs"},
		{scanType: "secrets", wantPath: "/secrets/scan-runs"},
	}

	for _, tt := range tests {
		t.Run(tt.scanType, func(t *testing.T) {
			var gotPath, gotScanType, gotRepo, gotLimit string
			c := testAPIClient(t, func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				q := r.URL.Query()
				gotScanType, gotRepo, gotLimit = q.Get("scanType"), q.Get("repositoryId"), q.Get("limit")
				_, _ = fmt.Fprint(w, `{"scanRuns":[]}`)
			})

			_, err := listScanRuns(context.Background(), c, tt.scanType, "repo-123", 10)
			require.NoError(t, err)
			require.Equal(t, tt.wantPath, gotPath)
			require.Equal(t, tt.wantScanType, gotScanType)
			require.Equal(t, "repo-123", gotRepo)
			require.Equal(t, "10", gotLimit)
		})
	}
}

func TestListScanRunsRejectsAnUnknownType(t *testing.T) {
	c := testAPIClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s", r.URL.Path)
	})

	_, err := listScanRuns(context.Background(), c, "dast", "repo-123", 0)
	require.ErrorContains(t, err, `invalid --type "dast"`)
	require.ErrorContains(t, err, "sca_containers")
}
