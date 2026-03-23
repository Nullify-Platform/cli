package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/stretchr/testify/require"
)

func TestResolveCommandAuthUsesEnvTokenWithoutStoredCredentials(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NULLIFY_HOST", "acme.nullify.ai")
	t.Setenv("NULLIFY_TOKEN", "env-token")

	originalHost := host
	originalNullifyToken := nullifyToken
	originalGithubToken := githubToken
	host = ""
	nullifyToken = ""
	githubToken = ""
	t.Cleanup(func() {
		host = originalHost
		nullifyToken = originalNullifyToken
		githubToken = originalGithubToken
	})

	authCtx, err := resolveCommandAuth(setupLogger(context.Background()))
	require.NoError(t, err)
	require.Equal(t, "acme.nullify.ai", authCtx.Host)
	require.Equal(t, "env-token", authCtx.Token)
	require.Empty(t, authCtx.QueryParams)
}

func TestResolveCommandAuthClonesStoredQueryParams(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NULLIFY_HOST", "acme.nullify.ai")
	t.Setenv("NULLIFY_TOKEN", "env-token")

	err := auth.SaveHostCredentials("acme.nullify.ai", auth.HostCredentials{
		AccessToken:  "stored-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		QueryParameters: map[string]string{
			"githubOwnerId": "123",
		},
	})
	require.NoError(t, err)

	originalHost := host
	originalNullifyToken := nullifyToken
	originalGithubToken := githubToken
	host = ""
	nullifyToken = ""
	githubToken = ""
	t.Cleanup(func() {
		host = originalHost
		nullifyToken = originalNullifyToken
		githubToken = originalGithubToken
	})

	authCtx, err := resolveCommandAuth(setupLogger(context.Background()))
	require.NoError(t, err)
	require.Equal(t, map[string]string{"githubOwnerId": "123"}, authCtx.QueryParams)

	authCtx.QueryParams["githubOwnerId"] = "456"

	creds, err := auth.LoadCredentials()
	require.NoError(t, err)
	require.Equal(t, "123", creds[auth.CredentialKey("acme.nullify.ai")].QueryParameters["githubOwnerId"])
}
