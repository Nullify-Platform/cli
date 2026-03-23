package lib

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/stretchr/testify/require"
)

func TestGetNullifyTokenPreservesStoredCredentialErrors(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NULLIFY_TOKEN", "")
	t.Setenv("GITHUB_ACTIONS", "")

	ctx, err := logger.ConfigureDevelopmentLogger(context.Background(), "error")
	require.NoError(t, err)

	// Save expired credentials without a refresh token
	err = auth.SaveHostCredentials("acme.nullify.ai", auth.HostCredentials{
		AccessToken: "expired-token",
		ExpiresAt:   time.Now().Add(-time.Hour).Unix(),
	})
	require.NoError(t, err)

	_, err = GetNullifyToken(ctx, "acme.nullify.ai", "", "")
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrNoToken),
		"should preserve stored credential error, not return generic ErrNoToken")
	require.Contains(t, err.Error(), "stored credentials")
}
