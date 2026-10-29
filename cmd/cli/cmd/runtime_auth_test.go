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

	authCtx, err := resolveCommandAuth(context.Background())
	require.NoError(t, err)
	require.Equal(t, "acme.nullify.ai", authCtx.Host)
	require.Equal(t, "env-token", authCtx.Token)
	require.Empty(t, authCtx.QueryParams)
}

// Logins before this CLI saved the server's default org (the lowest id) as
// query_parameters. That was never the user's choice, so it must not scope
// requests: an API token leaves the org to the server instead.
func TestResolveCommandAuthIgnoresLegacySavedScope(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NULLIFY_HOST", "acme.nullify.ai")
	t.Setenv("NULLIFY_TOKEN", "env-token")
	t.Setenv("NULLIFY_ORG", "")
	t.Setenv("NULLIFY_GITHUB_OWNER_ID", "")

	err := auth.SaveHostCredentials("acme.nullify.ai", auth.HostCredentials{
		AccessToken:  "stored-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		QueryParameters: map[string]string{
			"githubOwnerId": "123",
		},
	})
	require.NoError(t, err)
	stubOrgList(t, func(string) (auth.OrgList, error) {
		t.Error("an API token with no explicit org must not list orgs")
		return auth.OrgList{}, nil
	})

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

	authCtx, err := resolveCommandAuth(context.Background())
	require.NoError(t, err)
	require.Empty(t, authCtx.QueryParams)
}
