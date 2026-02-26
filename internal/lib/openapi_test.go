package lib

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/logger/pkg/logger"

	"github.com/stretchr/testify/require"
)

func TestCreateOpenAPIJSON(t *testing.T) {
	ctx, err := logger.ConfigureDevelopmentLogger(context.Background(), "debug")
	require.NoError(t, err)

	spec, err := CreateOpenAPIFile(ctx, "test/openapi.json")
	require.NoError(t, err)

	require.Equal(t, "3.0.0", spec["openapi"])

	input := client.DASTStartCloudScanInput{
		AppName:     "test",
		TargetHost:  "test.com",
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
	ctx, err := logger.ConfigureDevelopmentLogger(context.Background(), "debug")
	require.NoError(t, err)

	spec, err := CreateOpenAPIFile(ctx, "test/openapi.yml")
	require.NoError(t, err)

	require.Equal(t, "3.0.0", spec["openapi"])

	input := client.DASTStartCloudScanInput{
		AppName:     "test",
		TargetHost:  "test.com",
		OpenAPISpec: spec,
	}

	requestBody, err := json.Marshal(input)
	require.NoError(t, err)

	var input2 client.DASTStartCloudScanInput
	err = json.Unmarshal(requestBody, &input2)
	require.NoError(t, err)

	require.Equal(t, input, input2)
}
