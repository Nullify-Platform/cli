package cmd

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/commands"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestRuntimeErrorsSuppressUsage(t *testing.T) {
	root := &cobra.Command{Use: "test"}
	root.AddCommand(&cobra.Command{
		Use: "run",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("runtime failure")
		},
	})
	setRuntimeErrorBehavior(root)

	output := executeCommand(t, root, "run")

	require.Contains(t, output, "Error: runtime failure")
	require.NotContains(t, output, "Usage:")
}

func TestFrameworkErrorsIncludeUsage(t *testing.T) {
	root := &cobra.Command{Use: "test"}
	root.AddCommand(&cobra.Command{
		Use:  "run",
		RunE: func(cmd *cobra.Command, args []string) error { return nil },
	})
	setRuntimeErrorBehavior(root)

	output := executeCommand(t, root, "run", "--unknown")

	require.Contains(t, output, "unknown flag")
	require.Contains(t, output, "Usage:")
}

func TestStaticSilenceUsageSurvivesReset(t *testing.T) {
	root := &cobra.Command{Use: "test"}
	child := &cobra.Command{
		Use:          "run",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	root.AddCommand(child)
	defaults := captureCommandOutput(root)
	setRuntimeErrorBehavior(root)
	child.SilenceUsage = false
	resetCommandOutput(root, defaults)

	output := executeCommand(t, root, "run", "--unknown")

	require.Contains(t, output, "unknown flag")
	require.NotContains(t, output, "Usage:")
}

func TestGeneratedInputErrorsIncludeUsage(t *testing.T) {
	root := &cobra.Command{Use: "test"}
	commands.RegisterAdminCommands(
		root,
		func(context.Context) (*api.Client, error) {
			return &api.Client{}, nil
		},
	)
	setRuntimeErrorBehavior(root)

	output := executeCommand(
		t,
		root,
		"admin",
		"list-scan-coverage",
		"--limit",
		"invalid",
	)

	require.Contains(t, output, "invalid syntax")
	require.Contains(t, output, "Usage:")
}

func TestGeneratedClientFactoryErrorsReturnThroughCobra(t *testing.T) {
	want := errors.New("authentication failed")
	root := &cobra.Command{Use: "test"}
	commands.RegisterAdminCommands(
		root,
		func(context.Context) (*api.Client, error) {
			return nil, want
		},
	)
	setRuntimeErrorBehavior(root)
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"admin", "list-scan-coverage"})

	err := root.Execute()

	require.ErrorIs(t, err, want)
	require.NotContains(t, output.String(), "Usage:")
}

func TestGeneratedRuntimeErrorsIncludeUsage(t *testing.T) {
	root := &cobra.Command{Use: "test"}
	commands.RegisterAdminCommands(
		root,
		func(context.Context) (*api.Client, error) {
			return &api.Client{
				BaseURL: "https://example.com",
				HTTPClient: &http.Client{
					Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
						return nil, errors.New("connection refused")
					}),
				},
			}, nil
		},
	)
	setRuntimeErrorBehavior(root)

	output := executeCommand(t, root, "admin", "list-scan-coverage")

	require.Contains(t, output, "connection refused")
	require.Contains(t, output, "Usage:")
}

func TestContextDefaultFactoryErrorsSuppressUsage(t *testing.T) {
	want := errors.New("authentication failed")
	root := &cobra.Command{Use: "test"}
	commands.RegisterContextCommands(
		root,
		func(context.Context) (*api.Client, error) {
			return nil, want
		},
	)
	commands.ApplyContextCommandDefaults(
		root,
		func(context.Context) (*api.Client, error) {
			return nil, want
		},
	)
	setRuntimeErrorBehavior(root)
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"context", "get-project", "repo", "project"})

	err := root.Execute()

	require.ErrorIs(t, err, want)
	require.NotContains(t, output.String(), "Usage:")
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(
	req *http.Request,
) (*http.Response, error) {
	return fn(req)
}

func executeCommand(
	t *testing.T,
	root *cobra.Command,
	args ...string,
) string {
	t.Helper()

	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs(args)
	require.Error(t, root.Execute())
	return output.String()
}
