package wizard

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeMCPEnv is a project and a home directory in temporary directories, with
// a PATH that holds claude only when onPath is set. It records every command
// that the step runs instead of running it.
type fakeMCPEnv struct {
	env    mcpEnv
	ran    [][]string
	output string
	err    error
}

func newFakeMCPEnv(t *testing.T, onPath bool) *fakeMCPEnv {
	t.Helper()
	f := &fakeMCPEnv{}
	f.env = mcpEnv{
		projectRoot: t.TempDir(),
		home:        t.TempDir(),
		lookPath: func(file string) (string, error) {
			if onPath && file == "claude" {
				return "/usr/local/bin/claude", nil
			}
			return "", exec.ErrNotFound
		},
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			f.ran = append(f.ran, append([]string{name}, args...))
			return []byte(f.output), f.err
		},
	}
	return f
}

func (f *fakeMCPEnv) mkdir(t *testing.T, base, dir string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(base, dir), 0o700))
}

func readJSONFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}

func TestClaudeCodeIsAddedWithItsCLIWhenItIsOnThePath(t *testing.T) {
	f := newFakeMCPEnv(t, true)
	var out bytes.Buffer

	configureMCPClients(context.Background(), &out, f.env)

	require.Equal(t, [][]string{{"claude", "mcp", "add", "--scope", "user", "nullify", "--", "nullify", "mcp", "serve"}}, f.ran)
	require.Contains(t, out.String(), "Configured MCP for Claude Code (user scope)")
	require.NoFileExists(t, filepath.Join(f.env.projectRoot, ".mcp.json"))
	require.NoFileExists(t, filepath.Join(f.env.home, ".claude", "mcp.json"))
}

func TestClaudeCodeWithoutItsCLIGetsAProjectMCPFile(t *testing.T) {
	f := newFakeMCPEnv(t, false)
	f.mkdir(t, f.env.home, ".claude")
	var out bytes.Buffer

	configureMCPClients(context.Background(), &out, f.env)

	require.Empty(t, f.ran)
	path := filepath.Join(f.env.projectRoot, ".mcp.json")
	require.JSONEq(t, `{"mcpServers":{"nullify":{"command":"nullify","args":["mcp","serve"]}}}`, readJSONFile(t, path))
	require.Contains(t, out.String(), "Configured MCP for Claude Code ("+path+")")
	require.NoFileExists(t, filepath.Join(f.env.home, ".claude", "mcp.json"), "Claude Code does not read this file")
}

func TestClaudeCodeCLIFailure(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		configured bool
		want       string
	}{
		{name: "an existing entry counts as configured", output: "MCP server nullify already exists in user config", configured: true, want: "Claude Code already has a nullify MCP server"},
		{name: "another failure shows the command to run", output: "permission denied", want: "claude mcp add --scope user nullify -- nullify mcp serve"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeMCPEnv(t, true)
			f.output, f.err = tt.output, errors.New("exit status 1")
			var out bytes.Buffer

			configured := configureClaudeCode(context.Background(), &out, f.env)

			require.Equal(t, tt.configured, configured)
			require.Contains(t, out.String(), tt.want)
			require.NotContains(t, out.String(), "Configured MCP")
		})
	}
}

func TestVSCodeGetsServersWithTheStdioType(t *testing.T) {
	f := newFakeMCPEnv(t, false)
	f.mkdir(t, f.env.projectRoot, ".vscode")
	var out bytes.Buffer

	configureMCPClients(context.Background(), &out, f.env)

	path := filepath.Join(f.env.projectRoot, ".vscode", "mcp.json")
	require.JSONEq(t, `{"servers":{"nullify":{"type":"stdio","command":"nullify","args":["mcp","serve"]}}}`, readJSONFile(t, path))
	require.Contains(t, out.String(), "Configured MCP for VS Code ("+path+")")
}

func TestCursorGetsMCPServers(t *testing.T) {
	f := newFakeMCPEnv(t, false)
	f.mkdir(t, f.env.projectRoot, ".cursor")
	var out bytes.Buffer

	configureMCPClients(context.Background(), &out, f.env)

	path := filepath.Join(f.env.projectRoot, ".cursor", "mcp.json")
	require.JSONEq(t, `{"mcpServers":{"nullify":{"command":"nullify","args":["mcp","serve"]}}}`, readJSONFile(t, path))
	require.Contains(t, out.String(), "Configured MCP for Cursor ("+path+")")
}

func TestNoClientDetected(t *testing.T) {
	f := newFakeMCPEnv(t, false)
	var out bytes.Buffer

	configureMCPClients(context.Background(), &out, f.env)

	require.Empty(t, f.ran)
	require.Contains(t, out.String(), "No AI tools detected")
	require.False(t, strings.Contains(out.String(), "Configured"))
}
