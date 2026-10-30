package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
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
	require.Equal(t, "acme.nullify.ai", authCtx.AuthHost)
	require.Equal(t, "acme.nullify.ai", authCtx.DataHost)
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

	authCtx, err := resolveCommandAuth(context.Background())
	require.NoError(t, err)
	require.Equal(t, map[string]string{"githubOwnerId": "123"}, authCtx.QueryParams)

	authCtx.QueryParams["githubOwnerId"] = "456"

	creds, err := auth.LoadCredentials()
	require.NoError(t, err)
	require.Equal(t, "123", creds[auth.CredentialKey("acme.nullify.ai")].QueryParameters["githubOwnerId"])
}

func resetCommandFlags(t *testing.T) {
	t.Helper()
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
}

func saveRouterCredentials(t *testing.T, dataHost string) {
	t.Helper()
	require.NoError(t, auth.SaveHostCredentials(auth.RouterHost, auth.HostCredentials{
		AccessToken:     "router-token",
		RefreshToken:    "router-refresh",
		ExpiresAt:       time.Now().Add(time.Hour).Unix(),
		DataHost:        dataHost,
		Installation:    "acme",
		QueryParameters: map[string]string{"githubOwnerId": "7"},
	}))
}

func TestResolveCommandAuthHosts(t *testing.T) {
	tests := []struct {
		name         string
		configHost   string
		envHost      string
		flagHost     string
		envToken     string
		routerCreds  bool
		routerData   string
		tenantCreds  bool
		wantAuthHost string
		wantDataHost string
		wantToken    string
		wantParams   map[string]string
		wantErr      string
		githubCI     bool
		noHint       bool
	}{
		{
			name:         "router config uses the selected installation for data",
			configHost:   "nullify.ai",
			routerCreds:  true,
			routerData:   "acme.nullify.ai",
			wantAuthHost: "nullify.ai",
			wantDataHost: "acme.nullify.ai",
			wantToken:    "router-token",
			wantParams:   map[string]string{"githubOwnerId": "7"},
		},
		{
			name:         "router alias flag",
			flagHost:     "https://app.nullify.ai",
			routerCreds:  true,
			routerData:   "acme.nullify.ai",
			wantAuthHost: "nullify.ai",
			wantDataHost: "acme.nullify.ai",
			wantToken:    "router-token",
			wantParams:   map[string]string{"githubOwnerId": "7"},
		},
		{
			name:        "router without a selected installation fails",
			configHost:  "nullify.ai",
			routerCreds: true,
			routerData:  "",
			wantErr:     "no installation selected",
		},
		{
			name:       "router with an env token and no sign-in points CI at the instance",
			configHost: "nullify.ai",
			envToken:   "env-token",
			wantErr:    "set --host or NULLIFY_HOST to <instance>.nullify.ai",
		},
		{
			name:       "router with a GitHub Actions exchange and no sign-in points CI at the instance",
			configHost: "nullify.ai",
			githubCI:   true,
			wantErr:    "set --host or NULLIFY_HOST to <instance>.nullify.ai",
		},
		{
			name:        "tenant host ignores the router selection but hints at it",
			envHost:     "acme.nullify.ai",
			routerCreds: true,
			routerData:  "acme.nullify.ai",
			wantErr:     "not authenticated for acme.nullify.ai - run 'nullify auth login --host acme.nullify.ai' (signed in through nullify.ai - use --host nullify.ai or 'nullify auth switch --host nullify.ai')",
		},
		{
			name:        "tenant host without a matching router selection has no hint",
			envHost:     "beta.nullify.ai",
			routerCreds: true,
			routerData:  "acme.nullify.ai",
			wantErr:     "not authenticated for beta.nullify.ai - run 'nullify auth login --host beta.nullify.ai'",
			noHint:      true,
		},
		{
			name:         "tenant env token ignores router query parameters",
			envHost:      "acme.nullify.ai",
			envToken:     "env-token",
			routerCreds:  true,
			routerData:   "acme.nullify.ai",
			wantAuthHost: "acme.nullify.ai",
			wantDataHost: "acme.nullify.ai",
			wantToken:    "env-token",
			wantParams:   map[string]string{},
		},
		{
			name:         "tenant host uses its own credentials",
			envHost:      "acme.nullify.ai",
			routerCreds:  true,
			routerData:   "acme.nullify.ai",
			tenantCreds:  true,
			wantAuthHost: "acme.nullify.ai",
			wantDataHost: "acme.nullify.ai",
			wantToken:    "tenant-token",
			wantParams:   map[string]string{"githubOwnerId": "1"},
		},
		{
			name:         "other tenant stays on its own host",
			envHost:      "beta.nullify.ai",
			envToken:     "env-token",
			routerCreds:  true,
			routerData:   "acme.nullify.ai",
			wantAuthHost: "beta.nullify.ai",
			wantDataHost: "beta.nullify.ai",
			wantToken:    "env-token",
			wantParams:   map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("NULLIFY_HOST", tt.envHost)
			t.Setenv("NULLIFY_TOKEN", tt.envToken)
			t.Setenv("NULLIFY_GITHUB_OWNER_ID", "")
			t.Setenv("GITHUB_ACTIONS", "")
			t.Setenv("GITHUB_REPOSITORY", "")
			resetCommandFlags(t)
			host = tt.flagHost
			if tt.githubCI {
				t.Setenv("GITHUB_ACTIONS", "true")
				t.Setenv("GITHUB_REPOSITORY", "acme/repo")
				githubToken = "gh-token"
			}

			if tt.configHost != "" {
				require.NoError(t, auth.SaveConfig(&auth.Config{Host: tt.configHost}))
			}
			if tt.routerCreds {
				saveRouterCredentials(t, tt.routerData)
			}
			if tt.tenantCreds {
				require.NoError(t, auth.SaveHostCredentials("acme.nullify.ai", auth.HostCredentials{
					AccessToken:     "tenant-token",
					ExpiresAt:       time.Now().Add(time.Hour).Unix(),
					QueryParameters: map[string]string{"githubOwnerId": "1"},
				}))
			}

			authCtx, err := resolveCommandAuth(context.Background())
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				if tt.noHint {
					require.NotContains(t, err.Error(), "signed in through nullify.ai")
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantAuthHost, authCtx.AuthHost)
			require.Equal(t, tt.wantDataHost, authCtx.DataHost)
			require.Equal(t, tt.wantToken, authCtx.Token)
			require.Equal(t, tt.wantParams, authCtx.QueryParams)
			require.Equal(t, "https://api."+tt.wantDataHost, authCtx.APIClient().BaseURL)
			require.Equal(t, "https://api."+tt.wantDataHost, authCtx.Client().BaseURL)

			nullifyClient, err := getNullifyClientE(context.Background())
			require.NoError(t, err)
			require.Equal(t, "https://api."+tt.wantDataHost, nullifyClient.BaseURL)
		})
	}
}

func TestDashboardURL(t *testing.T) {
	tests := map[string]string{
		"nullify.ai":          "https://app.nullify.ai",
		"acme.nullify.ai":     "https://acme.nullify.ai",
		"api.acme.nullify.ai": "https://acme.nullify.ai",
	}
	for commandHost, want := range tests {
		require.Equal(t, want, dashboardURL(commandHost), commandHost)
	}
}

func TestMCPClientUsesAuthHostForTokensAndDataHostForRequests(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NULLIFY_TOKEN", "")
	t.Setenv("GITHUB_ACTIONS", "")
	resetCommandFlags(t)
	require.NoError(t, auth.SaveHostCredentials(auth.RouterHost, auth.HostCredentials{
		AccessToken: "router-token",
		ExpiresAt:   time.Now().Add(time.Hour).Unix(),
		DataHost:    "acme.nullify.ai",
	}))
	authCtx := &commandAuthContext{AuthHost: auth.RouterHost, DataHost: "acme.nullify.ai"}

	apiClient, err := newMCPAPIClient(context.Background(), authCtx, map[string]string{"repository": "r"})
	require.NoError(t, err)
	require.Equal(t, "https://api.acme.nullify.ai", apiClient.BaseURL)
	require.Equal(t, map[string]string{"repository": "r"}, apiClient.DefaultParams)

	tokenProvider, refreshProvider := mcpTokenProviders(context.Background(), authCtx.AuthHost)
	token, err := tokenProvider()
	require.NoError(t, err)
	require.Equal(t, "router-token", token)
	_, err = refreshProvider()
	require.ErrorIs(t, err, client.ErrTokenNotRefreshable, "refresh must look up the router credentials")

	dataTokenProvider, _ := mcpTokenProviders(context.Background(), authCtx.DataHost)
	_, err = dataTokenProvider()
	require.ErrorContains(t, err, "not authenticated for acme.nullify.ai")
}
