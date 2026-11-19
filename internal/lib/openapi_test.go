package lib

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nullify-platform/cli/internal/testutil"

	"github.com/stretchr/testify/require"
)

func TestCreateOpenAPIFileReadsJSONAndYAML(t *testing.T) {
	ctx, err := testutil.GetTestLogger()
	require.NoError(t, err)

	fromJSON, err := CreateOpenAPIFile(ctx, "test/openapi.json")
	require.NoError(t, err)
	fromYAML, err := CreateOpenAPIFile(ctx, "test/openapi.yml")
	require.NoError(t, err)

	require.Equal(t, "3.0.0", fromJSON["openapi"])
	require.Equal(t, "3.0.0", fromYAML["openapi"])

	// The spec is sent to the scanner as JSON, so a YAML spec must encode
	// without the map[interface{}]interface{} values YAML decodes to.
	for _, spec := range []map[string]any{fromJSON, fromYAML} {
		body, err := json.Marshal(spec)
		require.NoError(t, err)
		var decoded map[string]any
		require.NoError(t, json.Unmarshal(body, &decoded))
		require.NotNil(t, decoded["paths"])
	}
}

func TestCreateOpenAPIFileRejectsANonObject(t *testing.T) {
	ctx, err := testutil.GetTestLogger()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "spec.json")
	require.NoError(t, os.WriteFile(path, []byte(`["not", "a", "spec"]`), 0o600))

	_, err = CreateOpenAPIFile(ctx, path)

	require.ErrorContains(t, err, "JSON object")
}

func TestCreateOpenAPIFileReportsAMissingFile(t *testing.T) {
	ctx, err := testutil.GetTestLogger()
	require.NoError(t, err)

	_, err = CreateOpenAPIFile(ctx, filepath.Join(t.TempDir(), "missing.json"))

	require.ErrorIs(t, err, os.ErrNotExist)
}
