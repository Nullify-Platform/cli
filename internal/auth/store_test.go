package auth

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Writers that each rewrite the whole credentials file, as a terminal command
// and an MCP server do, keep every update: none reads the file before
// another's write lands and then saves over it.
func TestConcurrentCredentialWritesKeepEveryUpdate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			require.NoError(t, SaveHostCredentials(fmt.Sprintf("t%d.nullify.ai", i), HostCredentials{AccessToken: "a"}))
			require.NoError(t, UpdateHostConfig(fmt.Sprintf("t%d.nullify.ai", i), func(hc HostConfig) HostConfig {
				hc.AuthHost = "api.nullify.ai"
				return hc
			}))
		}()
	}
	wg.Wait()

	creds, err := LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 20)
	hosts, err := LoadHosts()
	require.NoError(t, err)
	require.Len(t, hosts, 20)
}

// Calls that all find the token rejected at once refresh it once and all use
// the new one.
func TestConcurrentForcedRefreshesRefreshOnce(t *testing.T) {
	var refreshes atomic.Int32
	newAuthServer(t, func(w http.ResponseWriter, r *http.Request) {
		refreshes.Add(1)
		time.Sleep(20 * time.Millisecond)
		refreshHandler(w, r)
	})
	seed(t, RouterHost, "rejected", "rt", time.Now().Add(time.Hour).Unix())

	var wg sync.WaitGroup
	tokens := make([]string, 20)
	for i := range tokens {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := ForceRefreshToken(context.Background(), RouterHost)
			require.NoError(t, err)
			tokens[i] = token
		}()
	}
	wg.Wait()

	require.Equal(t, int32(1), refreshes.Load())
	for _, token := range tokens {
		require.Equal(t, "new-id-token", token)
	}
}

// A refresh that finishes after a logout must not bring the login back, and
// one that finishes after a new login must not overwrite it.
func TestRefreshDoesNotOverwriteALoginThatChangedMeanwhile(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(t *testing.T)
		check  func(t *testing.T, creds Credentials)
	}{
		{
			name:   "logout",
			change: func(t *testing.T) { require.NoError(t, Logout(RouterHost)) },
			check: func(t *testing.T, creds Credentials) {
				_, ok := creds[RouterHost]
				require.False(t, ok, "the logged-out login came back")
			},
		},
		{
			name:   "new login",
			change: func(t *testing.T) { seed(t, RouterHost, "new-login", "new-rt", time.Now().Add(time.Hour).Unix()) },
			check: func(t *testing.T, creds Credentials) {
				require.Equal(t, "new-login", creds[RouterHost].AccessToken)
				require.Equal(t, "new-rt", creds[RouterHost].RefreshToken)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			newAuthServer(t, func(w http.ResponseWriter, r *http.Request) {
				tt.change(t)
				refreshHandler(w, r)
			})
			seed(t, RouterHost, "old", "old-rt", time.Now().Add(-time.Minute).Unix())

			_, err := GetValidToken(context.Background(), RouterHost)
			require.ErrorIs(t, err, errLoginReplaced)

			creds, err := LoadCredentials()
			require.NoError(t, err)
			tt.check(t, creds)
		})
	}
}

// A CLI v0.26.0 router login remembered its org only in the router
// credentials; that selection is this version's default for its data host,
// even after it stops being available, so the user is told instead of moved.
func TestStoredPickTakesOverTheV026Selection(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	require.Nil(t, StoredPick("globex.nullify.ai"))

	require.NoError(t, SaveHostCredentials(RouterHost, HostCredentials{
		AccessToken:     "t",
		DataHost:        "globex.nullify.ai",
		Installation:    "globex-web",
		QueryParameters: map[string]string{"githubOwnerId": "5005005"},
	}))
	require.Equal(t, &OrgPick{Name: "globex-web", Key: "githubOwnerId", ID: "5005005"}, StoredPick("globex.nullify.ai"))
	require.Nil(t, StoredPick("other.nullify.ai"))

	// A tenant's own login keeps the server's default org in the same
	// field; that was never the user's choice.
	require.NoError(t, SaveHostCredentials("acme.nullify.ai", HostCredentials{
		AccessToken:     "t",
		QueryParameters: map[string]string{"githubOwnerId": "1"},
	}))
	require.Nil(t, StoredPick("acme.nullify.ai"))

	require.NoError(t, UpdateHostConfig("globex.nullify.ai", func(hc HostConfig) HostConfig {
		hc.Org = &OrgPick{Name: "globex-ops", Key: "githubOwnerId", ID: "6006006"}
		return hc
	}))
	require.Equal(t, "6006006", StoredPick("globex.nullify.ai").ID, "a pick saved by this version wins")
}

// The selected data host of a v0.26.0 router login is covered by that login
// without asking the router.
func TestCoverSelectedTenantBindsTheV026DataHost(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	require.NoError(t, SaveHostCredentials(RouterHost, HostCredentials{AccessToken: "t", DataHost: "globex.nullify.ai"}))

	covered, err := CoverSelectedTenant("beta.nullify.ai")
	require.NoError(t, err)
	require.False(t, covered)

	covered, err = CoverSelectedTenant("globex.nullify.ai")
	require.NoError(t, err)
	require.True(t, covered)
	authHost, err := AuthHostFor("globex.nullify.ai")
	require.NoError(t, err)
	require.Equal(t, "api.nullify.ai", authHost)
}

// When the router cannot be asked whether its login covers a tenant, the
// command reports that, not "not authenticated".
func TestCoverTenantReportsARouterFailure(t *testing.T) {
	newAuthServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	seed(t, RouterHost, "router-token", "rt", time.Now().Add(time.Hour).Unix())

	covered, err := CoverTenant(context.Background(), "beta.nullify.ai")
	require.False(t, covered)
	require.ErrorContains(t, err, "could not check whether your nullify.ai login covers beta.nullify.ai")
}

// A dev router login is never asked about a production tenant: only a router
// whose domain can hold the tenant is checked, so its failure is not
// reported for a tenant it could never cover.
func TestCoverTenantAsksOnlyRoutersThatCanServeTheTenant(t *testing.T) {
	newAuthServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	seed(t, "router.dev.nullify.ai", "dev-token", "rt", time.Now().Add(time.Hour).Unix())

	covered, err := CoverTenant(context.Background(), "beta.nullify.ai")
	require.False(t, covered)
	require.NoError(t, err)

	_, err = CoverTenant(context.Background(), "sandbox.dev.nullify.ai")
	require.ErrorContains(t, err, "router.dev.nullify.ai login covers sandbox.dev.nullify.ai")
}
