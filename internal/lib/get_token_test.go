package lib

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/logger"
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

// A 401 retry is only worth making when the token source can produce a
// different token. The three fixed sources must say so with
// client.ErrTokenNotRefreshable rather than handing back the rejected value.
func TestRefreshNullifyTokenRejectsFixedSources(t *testing.T) {
	ctx, err := logger.ConfigureDevelopmentLogger(context.Background(), "error")
	require.NoError(t, err)

	tests := []struct {
		name      string
		tokenFlag string
		setup     func(t *testing.T)
	}{
		{
			name:      "nullify token flag",
			tokenFlag: "flag-token",
		},
		{
			name: "NULLIFY_TOKEN env",
			setup: func(t *testing.T) {
				t.Setenv("NULLIFY_TOKEN", "env-token")
			},
		},
		{
			name: "stored credentials without a refresh token",
			setup: func(t *testing.T) {
				require.NoError(t, auth.SaveHostCredentials("acme.nullify.ai", auth.HostCredentials{
					AccessToken: "stored-token",
					ExpiresAt:   time.Now().Add(time.Hour).Unix(),
				}))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("NULLIFY_TOKEN", "")
			t.Setenv("GITHUB_ACTIONS", "")
			if tt.setup != nil {
				tt.setup(t)
			}

			// The same inputs still resolve a token normally: forcing a refresh
			// is what changes the outcome, not the precedence chain.
			got, err := GetNullifyToken(ctx, "acme.nullify.ai", tt.tokenFlag, "")
			require.NoError(t, err)
			require.NotEmpty(t, got)

			_, err = RefreshNullifyToken(ctx, "acme.nullify.ai", tt.tokenFlag, "")
			require.ErrorIs(t, err, client.ErrTokenNotRefreshable)
		})
	}
}

func TestGetNullifyTokenRefusesGitHubExchangeOnRouter(t *testing.T) {
	ctx, err := logger.ConfigureDevelopmentLogger(context.Background(), "error")
	require.NoError(t, err)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NULLIFY_TOKEN", "")
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "acme/repo")

	for _, host := range []string{"nullify.ai", "api.nullify.ai", "app.nullify.ai"} {
		t.Run(host, func(t *testing.T) {
			_, err := GetNullifyToken(ctx, host, "", "gh-token")
			require.ErrorIs(t, err, errRouterGitHubExchange)
		})
	}
}

// The GitHub token exchange carries the GitHub token in its body: a redirect
// is returned as an error, never followed with that body.
func TestGitHubTokenExchangeDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed.Store(true)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	old := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = old })

	t.Setenv("NULLIFY_TOKEN", "")
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "acme/repo")

	_, err := GetNullifyToken(context.Background(), strings.TrimPrefix(srv.URL, "https://"), "", "gh-token")
	require.Error(t, err)
	require.False(t, followed.Load(), "the exchange followed a redirect")
}
