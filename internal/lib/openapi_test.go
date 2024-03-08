package lib

import (
	"encoding/json"
	"testing"

	"github.com/nullify-platform/cli/internal/client"

	"github.com/stretchr/testify/require"
)

func TestCreateOpenAPIJSON(t *testing.T) {
	spec, err := CreateOpenAPIFile("test/openapi.json")
	require.NoError(t, err)

	require.Equal(t, "3.0.0", spec["openapi"])

	input := client.DASTStartCloudScanInput{
		AppName:     "test",
		Host:        "test.com",
		OpenAPISpec: spec,
	}

	requestBody, err := json.Marshal(input)
	require.NoError(t, err)

	var input2 client.DASTStartCloudScanInput
	err = json.Unmarshal(requestBody, &input2)
	require.NoError(t, err)

	require.Equal(t, input, input2)
}

func TestCreateOpenAPIYAML(t *testing.T) {
	spec, err := CreateOpenAPIFile("test/openapi.yml")
	require.NoError(t, err)

	require.Equal(t, "3.0.0", spec["openapi"])

	input := client.DASTStartCloudScanInput{
		AppName:     "test",
		Host:        "test.com",
		OpenAPISpec: spec,
	}

	requestBody, err := json.Marshal(input)
	require.NoError(t, err)

	var input2 client.DASTStartCloudScanInput
	err = json.Unmarshal(requestBody, &input2)
	require.NoError(t, err)

	require.Equal(t, input, input2)
}
