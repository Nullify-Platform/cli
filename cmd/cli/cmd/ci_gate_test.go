package cmd

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/stretchr/testify/require"
)

func gateRequests(severities ...string) []string {
	want := []string{
		"/sca/dependencies/findings?isResolved=false&limit=1&repository=acme%2Fapp",
		"/sca/containers/findings?isResolved=false&limit=1&repository=acme%2Fapp",
		"/secrets/findings?isResolved=false&limit=1&repository=acme%2Fapp",
		"/dast/pentest/findings?isResolved=false&limit=1&repository=acme%2Fapp",
		"/dast/bughunt/findings?limit=1&repository=acme%2Fapp",
	}
	for _, severity := range severities {
		want = append(want,
			"/sast/findings?isResolved=false&limit=1&repository=acme%2Fapp&severity="+strings.ToUpper(severity),
			"/cspm/findings?limit=1&repository=acme%2Fapp&severity="+strings.ToUpper(severity)+"&status=open",
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
		{name: "a list route type", threshold: "critical", findType: "cspm", status: http.StatusOK, body: `{"findings":[]}`, exit: ExitSuccess, requests: []string{"/cspm/findings?limit=1&repository=acme%2Fapp&severity=CRITICAL&status=open"}},
		{name: "scpm is not a gate type", threshold: "critical", findType: "scpm", status: http.StatusOK, body: `{"findings":[]}`, exit: ExitSuccess, requests: gateRequests("critical")},
		{name: "sensitive data is not a gate type", threshold: "critical", findType: "secrets_sensitive_data", status: http.StatusOK, body: `{"findings":[]}`, exit: ExitSuccess, requests: gateRequests("critical")},
		{name: "a monorepo name is not a gate type", threshold: "critical", findType: "dast_pentest", status: http.StatusOK, body: `{"findings":[]}`, exit: ExitSuccess, requests: gateRequests("critical")},
		{name: "findings fail the gate", threshold: "critical", findType: "sast", status: http.StatusOK, body: `{"findings":[{"id":"f1"},{"id":"f2"}]}`, exit: ExitFindings, requests: []string{"/sast/findings?isResolved=false&limit=1&repository=acme%2Fapp&severity=CRITICAL"}},
		{name: "a total without findings fails closed", threshold: "critical", findType: "sast", status: http.StatusOK, body: `{"total":0}`, exit: ExitNetworkError, requests: []string{"/sast/findings?isResolved=false&limit=1&repository=acme%2Fapp&severity=CRITICAL"}},
		{name: "a failed request exits 3", threshold: "critical", findType: "sast", status: http.StatusForbidden, body: `{}`, exit: ExitNetworkError, requests: []string{"/sast/findings?isResolved=false&limit=1&repository=acme%2Fapp&severity=CRITICAL"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("NULLIFY_HOST", "acme.nullify.ai")
			t.Setenv("NULLIFY_TOKEN", "")
			require.ErrorIs(t, auth.SaveHostCredentials("acme.nullify.ai", auth.HostCredentials{AccessToken: "token", RefreshToken: "r", ExpiresAt: time.Now().Add(time.Hour).Unix()}), nil)

			var mu sync.Mutex
			var requests []string
			transport := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = transport })
			http.DefaultTransport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				requests = append(requests, r.URL.RequestURI())
				return &http.Response{StatusCode: tt.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(tt.body))}, nil
			})

			require.ErrorIs(t, ciGateCmd.Flags().Set("severity-threshold", tt.threshold), nil)
			require.ErrorIs(t, ciGateCmd.Flags().Set("type", tt.findType), nil)
			require.ErrorIs(t, ciGateCmd.Flags().Set("repo", "acme/app"), nil)
			ciGateCmd.SetContext(context.Background())

			err := ciGateCmd.RunE(ciGateCmd, nil)

			require.Equal(t, tt.exit, ExitCodeForError(err))
			slices.Sort(requests)
			require.Equal(t, tt.requests, requests)
		})
	}
}
