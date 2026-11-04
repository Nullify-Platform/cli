package cmd

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/apierror"
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
		{name: "no token", err: &apierror.APIError{StatusCode: http.StatusUnauthorized}, want: ExitAuthError},
		{name: "no access", err: &apierror.APIError{StatusCode: http.StatusForbidden}, want: ExitAuthError},
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
