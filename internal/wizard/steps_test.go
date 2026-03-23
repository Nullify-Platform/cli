package wizard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteMCPConfigPreservesUnknownTopLevelFields(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "mcp.json")

	err := os.WriteFile(configPath, []byte(`{
  "version": 1,
  "mcpServers": {
    "existing": {
      "command": "existing",
      "args": ["serve"]
    }
  },
  "other": {
    "enabled": true
  }
}`), 0600)
	require.NoError(t, err)

	err = writeMCPConfig(configPath)
	require.NoError(t, err)

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	require.Equal(t, float64(1), parsed["version"])

	other, ok := parsed["other"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, true, other["enabled"])

	mcpServers, ok := parsed["mcpServers"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, mcpServers, "existing")
	require.Contains(t, mcpServers, "nullify")
}
