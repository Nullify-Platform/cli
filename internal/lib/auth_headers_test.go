package lib

import (
	"context"
	"testing"

	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/stretchr/testify/require"
)

func TestParseAuthHeaders(t *testing.T) {
	ctx, err := logger.ConfigureDevelopmentLogger(context.Background(), "error")
	require.NoError(t, err)

	t.Run("accepts headers without a space after the colon", func(t *testing.T) {
		headers, err := ParseAuthHeaders(ctx, []string{"Authorization:Bearer token"})
		require.NoError(t, err)
		require.Equal(t, map[string]string{"Authorization": "Bearer token"}, headers)
	})

	t.Run("preserves commas in the header value", func(t *testing.T) {
		headers, err := ParseAuthHeaders(ctx, []string{"Cookie: a=b, c=d"})
		require.NoError(t, err)
		require.Equal(t, map[string]string{"Cookie": "a=b, c=d"}, headers)
	})

	t.Run("rejects malformed headers", func(t *testing.T) {
		_, err := ParseAuthHeaders(ctx, []string{"Authorization"})
		require.Error(t, err)
	})

	t.Run("warns on value resembling multiple headers", func(t *testing.T) {
		warnCtx, err := logger.ConfigureDevelopmentLogger(context.Background(), "warn")
		require.NoError(t, err)

		headers, err := ParseAuthHeaders(warnCtx, []string{"Authorization: Bearer token, X-Custom: value"})
		require.NoError(t, err)
		require.Equal(t, map[string]string{"Authorization": "Bearer token, X-Custom: value"}, headers)
	})
}
