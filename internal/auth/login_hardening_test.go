package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckAuthURL(t *testing.T) {
	tests := []struct {
		name     string
		authURL  string
		authHost string
		wantErr  bool
	}{
		{name: "instance api host", authURL: "https://api.acme.nullify.ai/auth/cli/start?session_id=s1", authHost: "acme.nullify.ai"},
		{name: "router api host", authURL: "https://api.nullify.ai/auth/cli/start?session_id=s1", authHost: "api.nullify.ai"},
		{name: "router tenant is a different origin", authURL: "https://api.acme.nullify.ai/auth/cli/start", authHost: RouterHost, wantErr: true},
		{name: "different port", authURL: "https://api.acme.nullify.ai:8443/auth/cli/start", authHost: "acme.nullify.ai", wantErr: true},
		{name: "explicit https port", authURL: "https://api.acme.nullify.ai:443/auth/cli/start", authHost: "acme.nullify.ai"},
		{name: "plain http", authURL: "http://api.acme.nullify.ai/auth/cli/start", authHost: "acme.nullify.ai", wantErr: true},
		{name: "another instance", authURL: "https://api.other.nullify.ai/auth/cli/start", authHost: "acme.nullify.ai", wantErr: true},
		{name: "lookalike domain", authURL: "https://api.acme.nullify.ai.example.com/auth", authHost: "acme.nullify.ai", wantErr: true},
		{name: "userinfo", authURL: "https://user@api.acme.nullify.ai/auth", authHost: "acme.nullify.ai", wantErr: true},
		{name: "not a web URL", authURL: "file:///etc/passwd", authHost: "acme.nullify.ai", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkAuthURL(tt.authURL, tt.authHost)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// tenantLoginServer is an instance that signs in itself and lists its own
// installations, which carry no base URL.
func tenantLoginServer(t *testing.T, token cliTokenResponse) *int {
	t.Helper()
	installationsCalls := 0
	newAuthServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/cli/session":
			var body struct {
				Port int `json:"port"`
			}
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			authURL := fmt.Sprintf("http://127.0.0.1:%d/callback?session_id=s1&redemption_secret=%s", body.Port, testRedemptionSecret)
			_ = json.NewEncoder(w).Encode(cliSessionResponse{SessionID: "s1", AuthURL: authURL})
		case "/auth/cli/token":
			_ = json.NewEncoder(w).Encode(token)
		case "/auth/cli/config":
			w.WriteHeader(http.StatusNotFound)
		case "/admin/installations":
			installationsCalls++
			_, _ = w.Write([]byte(`{"installations":[` +
				`{"name":"acme-main","provider":{},"queryParameters":{"githubOwnerId":"1"}},` +
				`{"name":"acme-labs","provider":{},"queryParameters":{"githubOwnerId":"2"}}]}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	stubBrowser(t)
	return &installationsCalls
}

var goodToken = cliTokenResponse{AccessToken: "access", RefreshToken: "refresh", ExpiresIn: 3600}

func TestLoginTenantHostHonoursOrg(t *testing.T) {
	calls := tenantLoginServer(t, goodToken)

	require.NoError(t, Login(context.Background(), "acme.nullify.ai", InstallationPicker{Name: "acme-labs"}))

	require.Equal(t, 1, *calls)
	hosts, err := LoadHosts()
	require.NoError(t, err)
	require.NotNil(t, hosts["acme.nullify.ai"].Org)
	require.Equal(t, "2", hosts["acme.nullify.ai"].Org.ID)
}

func TestLoginTenantHostUnknownOrgSavesNothing(t *testing.T) {
	tenantLoginServer(t, goodToken)

	err := Login(context.Background(), "acme.nullify.ai", InstallationPicker{Name: "nope"})

	require.ErrorContains(t, err, `organization "nope" not found`)
	creds, err := LoadCredentials()
	if err == nil {
		_, ok := creds["acme.nullify.ai"]
		require.False(t, ok, "a login with an unknown --org must not be saved")
	} else {
		require.ErrorIs(t, err, os.ErrNotExist)
	}
}

func TestLoginRejectsUnusableToken(t *testing.T) {
	tests := map[string]cliTokenResponse{
		"empty access token": {RefreshToken: "refresh", ExpiresIn: 3600},
		"no lifetime":        {AccessToken: "access", RefreshToken: "refresh"},
	}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			tenantLoginServer(t, token)

			err := Login(context.Background(), "acme.nullify.ai", InstallationPicker{})

			require.ErrorContains(t, err, "no usable token")
		})
	}
}

// Logout revokes the stored refresh token at the auth host, then deletes the
// local credentials even when the revocation fails.
func TestRevokeLoginSendsTheRefreshToken(t *testing.T) {
	tests := map[string]int{"revoked": http.StatusOK, "server error": http.StatusInternalServerError}
	for name, status := range tests {
		t.Run(name, func(t *testing.T) {
			var gotCookie string
			newAuthServer(t, func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/auth/logout", r.URL.Path)
				require.Equal(t, http.MethodGet, r.Method)
				if c, err := r.Cookie("refresh_token"); err == nil {
					gotCookie = c.Value
				}
				w.WriteHeader(status)
			})
			require.NoError(t, SaveHostCredentials("acme.nullify.ai", HostCredentials{
				AccessToken: "access", RefreshToken: "refresh-1", ExpiresAt: 1,
			}))

			err := RevokeLogin(context.Background(), "acme.nullify.ai")
			if status == http.StatusOK {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "status 500")
			}
			require.Equal(t, "refresh-1", gotCookie)

			require.NoError(t, Logout("acme.nullify.ai"))
			creds, err := LoadCredentials()
			require.NoError(t, err)
			require.NotContains(t, creds, "acme.nullify.ai")
		})
	}
}

type logoutTransport func(*http.Request) (*http.Response, error)

func (f logoutTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRevokeLoginWithOnlyLegacyTenantCredential(t *testing.T) {
	const host = "acme.nullify.ai"
	t.Setenv("HOME", t.TempDir())
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	var revoked string
	httpClient = &http.Client{Transport: logoutTransport(func(req *http.Request) (*http.Response, error) {
		require.Equal(t, apiHost(host), req.URL.Host)
		cookie, err := req.Cookie("refresh_token")
		require.NoError(t, err)
		revoked = cookie.Value
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})}
	require.NoError(t, SaveHostCredentials(host, HostCredentials{RefreshToken: "legacy"}))
	require.NoError(t, BindTenant(host, routers[0]))

	require.NoError(t, RevokeLogin(context.Background(), host))
	require.Equal(t, "legacy", revoked)
}

func TestRevokeLoginWithoutStoredLoginDoesNothing(t *testing.T) {
	newAuthServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
	})
	require.NoError(t, RevokeLogin(context.Background(), "acme.nullify.ai"))
}

// ~/.nullify holds tokens: an existing directory with looser permissions is
// tightened to 0700, and a symlink in its place is refused.
func TestEnsureConfigDirTightensPermissions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := home + "/.nullify"
	require.NoError(t, os.Mkdir(dir, 0755))

	require.NoError(t, ensureConfigDir())

	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0700), info.Mode().Perm())
}

func TestEnsureConfigDirFollowsSymlinkToDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	target := t.TempDir()
	require.NoError(t, os.Chmod(target, 0755))
	require.NoError(t, os.Symlink(target, home+"/.nullify"))

	require.NoError(t, ensureConfigDir())

	info, err := os.Stat(target)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0700), info.Mode().Perm())
}

func TestEnsureConfigDirRefusesAFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	require.NoError(t, os.WriteFile(home+"/.nullify", []byte("x"), 0600))

	require.Error(t, ensureConfigDir())
}

// A token that can be refreshed is replaced six minutes early, so the MCP
// token cache never serves an expired one. A token with no refresh token is
// used until it really expires, since nothing can replace it.
func TestExpiredLeewayAppliesOnlyToRefreshableTokens(t *testing.T) {
	soon := time.Now().Add(3 * time.Minute).Unix()
	tests := []struct {
		name  string
		creds HostCredentials
		want  bool
	}{
		{name: "refreshable, inside leeway", creds: HostCredentials{RefreshToken: "r", ExpiresAt: soon}, want: true},
		{name: "refreshable, well before expiry", creds: HostCredentials{RefreshToken: "r", ExpiresAt: time.Now().Add(time.Hour).Unix()}, want: false},
		{name: "not refreshable, inside leeway", creds: HostCredentials{ExpiresAt: soon}, want: false},
		{name: "not refreshable, past expiry", creds: HostCredentials{ExpiresAt: time.Now().Add(-time.Second).Unix()}, want: true},
		{name: "no expiry recorded", creds: HostCredentials{RefreshToken: "r"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, expired(tt.creds))
		})
	}
}

func TestCheckAuthURLAcceptsRouterTenantSignIn(t *testing.T) {
	require.NoError(t, checkAuthURL("https://api.nullify.ai/auth/cli/start?session_id=s1", RouterHost))
}

func TestAuthRequestsSendUserAgent(t *testing.T) {
	var got string
	newAuthServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	})
	require.NoError(t, SaveHostCredentials("acme.nullify.ai", HostCredentials{AccessToken: "a", RefreshToken: "r", ExpiresAt: 1}))

	require.NoError(t, RevokeLogin(context.Background(), "acme.nullify.ai"))

	require.Contains(t, got, "Nullify-CLI/")
}
