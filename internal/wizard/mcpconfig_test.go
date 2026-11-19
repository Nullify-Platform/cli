package wizard

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteMCPConfig(t *testing.T) {
	format := mcpConfigFormat{key: "mcpServers", entry: map[string]any{"command": "nullify", "args": []string{"mcp", "serve"}}}

	tests := []struct {
		name     string
		existing *string
		mode     os.FileMode
		added    bool
		err      error
		want     string
	}{
		{
			name:  "a new file holds only the entry",
			added: true,
			mode:  0o600,
			want:  `{"mcpServers":{"nullify":{"command":"nullify","args":["mcp","serve"]}}}`,
		},
		{
			name:     "an empty file is a new file",
			existing: ptr("  \n"),
			mode:     0o600,
			added:    true,
			want:     `{"mcpServers":{"nullify":{"command":"nullify","args":["mcp","serve"]}}}`,
		},
		{
			name:     "other servers and fields are kept and the mode is kept",
			existing: ptr(`{"version":1,"mcpServers":{"other":{"command":"other"}},"extra":{"on":true}}`),
			mode:     0o644,
			added:    true,
			want:     `{"version":1,"mcpServers":{"other":{"command":"other"},"nullify":{"command":"nullify","args":["mcp","serve"]}},"extra":{"on":true}}`,
		},
		{
			name:     "an existing nullify entry is left alone",
			existing: ptr(`{"mcpServers":{"nullify":{"command":"/opt/nullify"}}}`),
			mode:     0o644,
			want:     `{"mcpServers":{"nullify":{"command":"/opt/nullify"}}}`,
		},
		{
			name:     "a file with comments is refused",
			existing: ptr("{\n  // my servers\n  \"mcpServers\": {}\n}"),
			mode:     0o644,
			err:      ErrUnreadableMCPConfig,
		},
		{
			name:     "a file with a trailing comma is refused",
			existing: ptr(`{"mcpServers":{"other":{"command":"other"},}}`),
			mode:     0o644,
			err:      ErrUnreadableMCPConfig,
		},
		{
			name:     "a file that is not an object is refused",
			existing: ptr(`["nullify"]`),
			mode:     0o644,
			err:      ErrUnreadableMCPConfig,
		},
		{
			name:     "a servers value that is not an object is refused",
			existing: ptr(`{"mcpServers":"none"}`),
			mode:     0o644,
			err:      ErrUnreadableMCPConfig,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "mcp.json")
			if tt.existing != nil {
				require.NoError(t, os.WriteFile(path, []byte(*tt.existing), tt.mode))
				require.NoError(t, os.Chmod(path, tt.mode))
			}

			added, err := writeMCPConfig(path, format)

			require.ErrorIs(t, err, tt.err)
			require.Equal(t, tt.added, added)
			data, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			if tt.err != nil {
				require.Equal(t, *tt.existing, string(data), "a refused file must not change")
			} else {
				require.JSONEq(t, tt.want, string(data))
			}
			info, statErr := os.Stat(path)
			require.NoError(t, statErr)
			require.Equal(t, tt.mode, info.Mode().Perm())
			entries, dirErr := os.ReadDir(dir)
			require.NoError(t, dirErr)
			require.Len(t, entries, 1, "no temporary file is left behind")
		})
	}
}

func TestWriteMCPConfigWritesThroughASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dotfiles-mcp.json")
	require.NoError(t, os.WriteFile(target, []byte(`{}`), 0o600))
	link := filepath.Join(dir, "mcp.json")
	require.NoError(t, os.Symlink(target, link))

	added, err := writeMCPConfig(link, mcpConfigFormat{key: "servers", entry: map[string]any{"command": "nullify"}})

	require.NoError(t, err)
	require.True(t, added)
	info, err := os.Lstat(link)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSymlink, "the link stays a link")
	data, err := os.ReadFile(target)
	require.NoError(t, err)
	require.JSONEq(t, `{"servers":{"nullify":{"command":"nullify"}}}`, string(data))
}

func TestMCPConfigSnippetIsTheEntryUnderItsKey(t *testing.T) {
	snippet := mcpConfigFormat{key: "servers", entry: map[string]any{"type": "stdio", "command": "nullify"}}.snippet()

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(snippet), &parsed))
	require.Equal(t, map[string]any{"servers": map[string]any{"nullify": map[string]any{"type": "stdio", "command": "nullify"}}}, parsed)
}

func TestConfigureByFileShowsTheEntryWhenItRefuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	require.NoError(t, os.WriteFile(path, []byte("{\n  // keep me\n}"), 0o644))
	var out bytes.Buffer

	ok := configureByFile(&out, "VS Code", path, mcpConfigFormat{key: "servers", entry: map[string]any{"type": "stdio"}})

	require.False(t, ok)
	require.NotContains(t, out.String(), "Configured")
	require.Contains(t, out.String(), "left unchanged")
	require.Contains(t, out.String(), `"servers"`)
	require.Contains(t, out.String(), `"nullify"`)
}

func ptr(s string) *string { return &s }
