package commands

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

type contextUploadTransport func(*http.Request) (*http.Response, error)

func (f contextUploadTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestContextPushRejectsIncompleteUploadCredentials(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "plan.json")
	require.NoError(t, os.WriteFile(filePath, []byte("{}"), 0o600))
	t.Setenv("GITHUB_SHA", "fixture-commit")
	root := &cobra.Command{Use: "api", SilenceErrors: true, SilenceUsage: true}
	calls := 0
	RegisterContextPushCommand(root, func(context.Context) (*api.Client, error) {
		return &api.Client{
			BaseURL:       "https://example.com",
			DefaultParams: map[string]string{"githubOwnerId": "42"},
			HTTPClient: &http.Client{Transport: contextUploadTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				require.Equal(t, http.MethodPost, req.Method)
				require.Equal(t, "/admin/context/ingest", req.URL.Path)
				require.Equal(t, "42", req.URL.Query().Get("githubOwnerId"))
				body, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				require.JSONEq(t, `{"contextType":"terraform","repository":"org/repo","branch":"main","name":"networking","commitSha":"fixture-commit"}`, string(body))
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("{}")),
				}, nil
			})},
		}, nil
	})
	root.SetArgs([]string{"context", "push", filePath, "--type", "terraform",
		"--repository", "org/repo", "--branch", "main", "--name", "networking"})

	require.ErrorContains(t, root.ExecuteContext(t.Context()), "incomplete context upload credentials")
	require.Equal(t, 1, calls)
}
