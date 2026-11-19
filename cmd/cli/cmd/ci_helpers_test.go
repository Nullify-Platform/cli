package cmd

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

// ciPlatformEnvs are the env vars that identify a CI platform or name the
// repository it builds. Tests clear them so the CI that runs the tests
// cannot change what a command detects.
var ciPlatformEnvs = []string{
	"GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "BITBUCKET_BUILD_NUMBER",
	"JENKINS_URL", "TF_BUILD", "BUILD_ID", "PROJECT_ID", "CODEBUILD_BUILD_ID",
	"GITHUB_REPOSITORY_ID", "CI_PROJECT_ID", "BITBUCKET_REPO_UUID",
	"BUILD_REPOSITORY_ID", "BUILD_REPOSITORY_PROVIDER",
}

// useCIEnv points the CLI at a synthetic tenant with an API token, so a CI
// command resolves its auth without a login or a router. It also clears
// every CI platform variable.
func useCIEnv(t *testing.T) {
	t.Helper()
	for _, name := range ciPlatformEnvs {
		t.Setenv(name, "")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NULLIFY_HOST", "acme.nullify.ai")
	t.Setenv("NULLIFY_TOKEN", "synthetic")
	originalHost, originalToken, originalGithub := host, nullifyToken, githubToken
	host, nullifyToken, githubToken = "acme.nullify.ai", "synthetic", ""
	t.Cleanup(func() {
		host, nullifyToken, githubToken = originalHost, originalToken, originalGithub
	})
}

// fakeScannerAPI records every request a CI command sends and answers each
// one with the status and body that respond returns.
type fakeScannerAPI struct {
	mu       sync.Mutex
	received []string
}

func serveScannerAPI(t *testing.T, respond func(*http.Request) (int, string)) *fakeScannerAPI {
	t.Helper()
	api := &fakeScannerAPI{}
	transport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = transport })
	http.DefaultTransport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		api.mu.Lock()
		api.received = append(api.received, r.URL.RequestURI())
		api.mu.Unlock()
		status, body := respond(r)
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}, nil
	})
	return api
}

// requests returns the recorded request URIs in sorted order.
func (a *fakeScannerAPI) requests() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	sorted := slices.Clone(a.received)
	slices.Sort(sorted)
	return sorted
}

// emptyFindings answers every scanner route with an empty page.
func emptyFindings(*http.Request) (int, string) {
	return http.StatusOK, `{"findings":[],"numItems":0}`
}

// runCI runs a CI command with the given flags set, from a clean flag state,
// and returns what it printed to stdout.
func runCI(t *testing.T, c *cobra.Command, flags map[string]string) (string, error) {
	t.Helper()
	resetFlags(t, c)
	t.Cleanup(func() { resetFlags(t, c) })
	for name, value := range flags {
		require.NoError(t, c.Flags().Set(name, value))
	}
	c.SetContext(context.Background())

	var err error
	out := captureStdout(t, func() { err = c.RunE(c, nil) })
	return out, err
}

func resetFlags(t *testing.T, c *cobra.Command) {
	t.Helper()
	c.Flags().VisitAll(func(f *pflag.Flag) {
		require.NoError(t, f.Value.Set(f.DefValue))
		f.Changed = false
	})
}
