package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/apierror"
	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/commands"
	"github.com/nullify-platform/cli/internal/findings"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

const surfaceSnapshot = "../../../spec/command-surface.tsv"

func TestCommandSurfaceMatchesSnapshot(t *testing.T) {
	content, err := os.ReadFile(surfaceSnapshot)
	require.ErrorIs(t, err, nil)
	snapshot, err := commands.ParseSurface(string(content))
	require.ErrorIs(t, err, nil)

	live := commands.Surface(rootCmd)

	require.ErrorIs(t, commands.CheckSurface(snapshot, live, commands.Decisions), nil)
	require.ErrorIs(t, commands.CheckSnapshotComplete(snapshot, live), nil)
	require.Equal(t, string(content), commands.FormatSurface(live), "run make command-surface")
}

func TestRemovedCommandsStayRemoved(t *testing.T) {
	live := map[string]bool{}
	for _, e := range commands.Surface(rootCmd) {
		live[e.Command] = true
	}

	for _, removed := range commands.Decisions.RemovedCommands {
		t.Run(removed.Command, func(t *testing.T) {
			require.False(t, live[removed.Command])
		})
	}
}

func TestMovedCommandsCallTheNewRoute(t *testing.T) {
	byPath := map[string]string{}
	for _, e := range commands.Surface(rootCmd) {
		byPath[e.Command] = e.Route
	}

	for _, moved := range commands.Decisions.Moved {
		t.Run(moved.From, func(t *testing.T) {
			require.NotEmpty(t, byPath[moved.To])
			require.Equal(t, byPath[moved.To], byPath[moved.From])
		})
	}
}

func TestMovedCommandRunsAndWarns(t *testing.T) {
	var requested string
	root := &cobra.Command{Use: "nullify"}
	apiRoot := &cobra.Command{Use: "api"}
	root.AddCommand(apiRoot)
	commands.RegisterAPICommands(apiRoot, func(context.Context) (*api.Client, error) {
		return &api.Client{
			BaseURL: "https://example.com",
			HTTPClient: &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				requested = r.URL.Path
				return nil, fmt.Errorf("stop")
			})},
		}, nil
	})
	commands.ApplySurfaceDecisions(root, commands.Decisions)

	var stderr bytes.Buffer
	root.SetErr(&stderr)
	root.SetOut(&stderr)
	root.SetArgs([]string{"api", "asset-graph", "list-search", "--q", "bucket"})

	require.Error(t, root.Execute())

	require.Equal(t, "/context/asset-graph/search", requested)
	require.Contains(t, stderr.String(), "nullify api context list-search")
}

func TestFindingVerbsRequireTheirFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "allowlist needs every flag", args: []string{"findings", "allowlist", "f1"}, want: `required flag(s) "allowlist-type", "reason", "type" not set`},
		{name: "allowlist needs an explicit allowlist type", args: []string{"findings", "allowlist", "f1", "--type", "cspm", "--reason", "r"}, want: `required flag(s) "allowlist-type" not set`},
		{name: "allowlist needs a reason", args: []string{"findings", "allowlist", "f1", "--type", "cspm", "--allowlist-type", "UserFixed"}, want: `required flag(s) "reason" not set`},
		{name: "unallowlist needs a reason", args: []string{"findings", "unallowlist", "f1", "--type", "cspm"}, want: `required flag(s) "reason" not set`},
		{name: "mark false positive needs a reason", args: []string{"findings", "mark-false-positive", "f1", "--type", "cspm"}, want: `required flag(s) "reason" not set`},
		{name: "archive needs a type", args: []string{"findings", "archive", "f1"}, want: `required flag(s) "type" not set`},
		{name: "feedback needs a verdict", args: []string{"findings", "feedback", "f1"}, want: `required flag(s) "verdict" not set`},
		{name: "a typo in a verb is not a list", args: []string{"findings", "alowlist", "f1"}, want: `unknown command`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := &cobra.Command{Use: "findings", Args: cobra.NoArgs, RunE: runFindingsList}
			addFindingVerbCommands(parent)
			root := &cobra.Command{Use: "nullify"}
			root.AddCommand(parent)

			output := executeCommand(t, root, tt.args...)

			require.Contains(t, output, tt.want)
		})
	}
}

func TestFindingsRepository(t *testing.T) {
	detect := func() string { return "detected-repo" }

	tests := []struct {
		name     string
		flag     string
		apiTypes []string
		want     string
	}{
		{name: "no type uses the working directory", want: "detected-repo"},
		{name: "a code search uses the working directory", apiTypes: []string{"Code"}, want: "detected-repo"},
		{name: "a scpm search uses the working directory", apiTypes: []string{"SupplyChain"}, want: "detected-repo"},
		{name: "a cloud search ignores the working directory", apiTypes: []string{"Cloud"}, want: ""},
		{name: "an explicit repository always wins", flag: "other", apiTypes: []string{"Cloud"}, want: "other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, findingsRepository(tt.flag, tt.apiTypes, detect))
		})
	}
}

func TestFindingsErrorExitCodes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "no token", err: &apierror.APIError{StatusCode: http.StatusUnauthorized}, want: ExitNetworkError},
		{name: "no access", err: &apierror.APIError{StatusCode: http.StatusForbidden}, want: ExitNetworkError},
		{name: "server failure", err: &apierror.APIError{StatusCode: http.StatusInternalServerError}, want: ExitNetworkError},
		{name: "transport failure", err: fmt.Errorf("connection refused"), want: ExitNetworkError},
		{name: "unknown type", err: findings.ErrUnknownType, want: 1},
		{name: "unsupported", err: findings.ErrUnsupported, want: 1},
		{name: "bad limit", err: findings.ErrInvalidLimit, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ExitCodeForError(findingsError(tt.err)))
		})
	}
}

func TestReportFixExitCode(t *testing.T) {
	tests := []struct {
		name   string
		result findings.FixResult
		want   int
	}{
		{name: "success", result: findings.FixResult{State: "cached"}, want: ExitSuccess},
		{name: "failed", result: findings.FixResult{State: "failed_abort", Failure: findings.ErrAutofixFailed}, want: 1},
		{name: "still running", result: findings.FixResult{StillRunning: true, Failure: findings.ErrAutofixStillRunning}, want: 1},
		{name: "no new pull request", result: findings.FixResult{State: "pending_review", Failure: findings.ErrNoPullRequest}, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{Use: "fix"}
			cmd.SetOut(&bytes.Buffer{})

			require.Equal(t, tt.want, ExitCodeForError(reportFix(cmd, "f1", "sast", tt.result)))
		})
	}
}

func TestRunFix(t *testing.T) {
	const started = `{"autoFixState":"in_progress_requested","runId":"r1"}`
	const running = `{"status":{"state":"in_progress_agent","terminal":false}}`
	const failed = `{"status":{"state":"failed_abort","terminal":true}}`

	tests := []struct {
		name     string
		noWait   bool
		status   string
		timeout  time.Duration
		exit     int
		requests []string
	}{
		{name: "no-wait starts the run and exits 0", noWait: true, status: failed, exit: ExitSuccess, requests: []string{"POST /sast/findings/f1/autofix/fix"}},
		{name: "a failed run exits 1", status: failed, timeout: time.Minute, exit: 1, requests: []string{"POST /sast/findings/f1/autofix/fix", "GET /sast/findings/f1/autofix/status"}},
		{name: "a timed-out run exits 1", status: running, timeout: time.Nanosecond, exit: 1, requests: []string{"POST /sast/findings/f1/autofix/fix", "GET /sast/findings/f1/autofix/status"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests []string
			c := &api.Client{
				BaseURL: "https://example.com",
				HTTPClient: &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
					requests = append(requests, r.Method+" "+r.URL.Path)
					body := started
					if r.Method == http.MethodGet {
						body = tt.status
					}
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
				})},
			}
			cmd := &cobra.Command{Use: "fix"}
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetContext(context.Background())

			err := runFix(cmd, c, "f1", "sast", tt.noWait, findings.FixOptions{Timeout: tt.timeout})

			require.Equal(t, tt.exit, ExitCodeForError(err))
			require.Equal(t, tt.requests, requests)
		})
	}
}

func TestFixWaitFlags(t *testing.T) {
	require.Equal(t, "50m0s", fixCmd.Flags().Lookup("timeout").DefValue)
	require.Equal(t, "false", fixCmd.Flags().Lookup("no-wait").DefValue)
}

func TestFixCommandSurvivesATokenExpiry(t *testing.T) {
	tests := []struct {
		name        string
		refreshCode int
		exit        int
		stdout      []string
	}{
		{name: "a refreshed token continues the wait", refreshCode: http.StatusOK, exit: ExitSuccess, stdout: []string{`"state": "cached"`, `"run_id": "r1"`}},
		{name: "a failed refresh prints the partial result", refreshCode: http.StatusUnauthorized, exit: ExitNetworkError, stdout: []string{`"state": "in_progress_requested"`, `"run_id": "r1"`, `"check_with": "nullify findings fix-status f1 --type sast"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("NULLIFY_HOST", "acme.nullify.ai")
			t.Setenv("NULLIFY_TOKEN", "")
			require.ErrorIs(t, auth.SaveHostCredentials("acme.nullify.ai", auth.HostCredentials{AccessToken: "old", RefreshToken: "r", ExpiresAt: time.Now().Add(time.Hour).Unix()}), nil)

			respond := func(code int, body string) (*http.Response, error) {
				return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
			}
			transport := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = transport })
			http.DefaultTransport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/auth/refresh_token"):
					return respond(tt.refreshCode, `{"accessToken":"new","expiresIn":3600}`)
				case strings.HasSuffix(r.URL.Path, "/autofix/fix"):
					return respond(http.StatusOK, `{"autoFixState":"in_progress_requested","runId":"r1"}`)
				case r.Header.Get("Authorization") != "Bearer new":
					return respond(http.StatusUnauthorized, `{}`)
				}
				return respond(http.StatusOK, `{"status":{"state":"cached","terminal":true}}`)
			})

			read, write, err := os.Pipe()
			require.ErrorIs(t, err, nil)
			stdout := os.Stdout
			t.Cleanup(func() { os.Stdout = stdout })
			os.Stdout = write

			require.ErrorIs(t, fixCmd.Flags().Set("type", "sast"), nil)
			fixCmd.SetContext(context.Background())
			runErr := fixCmd.RunE(fixCmd, []string{"f1"})

			require.ErrorIs(t, write.Close(), nil)
			out, err := io.ReadAll(read)
			require.ErrorIs(t, err, nil)

			require.Equal(t, tt.exit, ExitCodeForError(runErr))
			for _, want := range tt.stdout {
				require.Contains(t, string(out), want)
			}
		})
	}
}
