package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRedemptionSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type fakeLoginServer struct {
	installations      string
	installationsCalls int
}

func (f *fakeLoginServer) handle(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/cli/session":
			var body struct {
				Port int `json:"port"`
			}
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			authURL := fmt.Sprintf("http://127.0.0.1:%d/callback?session_id=s1&redemption_secret=%s", body.Port, testRedemptionSecret)
			_ = json.NewEncoder(w).Encode(cliSessionResponse{SessionID: "s1", AuthURL: authURL})
		case "/auth/cli/token":
			_ = json.NewEncoder(w).Encode(cliTokenResponse{
				AccessToken:     "access",
				RefreshToken:    "refresh",
				ExpiresIn:       3600,
				QueryParameters: map[string]string{"fromToken": "1"},
			})
		case "/admin/installations":
			f.installationsCalls++
			assert.Equal(t, "Bearer access", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(f.installations))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// recordAuthHosts records the host argument of every authBaseURL call.
func recordAuthHosts(t *testing.T) *[]string {
	t.Helper()
	var mu sync.Mutex
	hosts := []string{}
	old := authBaseURL
	authBaseURL = func(host string) string {
		mu.Lock()
		defer mu.Unlock()
		hosts = append(hosts, host)
		return old(host)
	}
	t.Cleanup(func() { authBaseURL = old })
	return &hosts
}

func requireOnlyRouterHost(t *testing.T, hosts []string, wantCalls int) {
	t.Helper()
	require.Len(t, hosts, wantCalls)
	for _, host := range hosts {
		require.Equal(t, RouterHost, host)
	}
}

// stubBrowser completes the browser step by calling the local callback URL.
func stubBrowser(t *testing.T) {
	t.Helper()
	old := openBrowser
	openBrowser = func(url string) error {
		go func() {
			resp, err := http.Get(url)
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
	t.Cleanup(func() { openBrowser = old })
}

func installationJSON(name, baseURL string) string {
	return fmt.Sprintf(`{"name":%q,"avatarUrl":"","provider":{},"nullifyBaseUrl":%q,"queryParameters":{"githubOwnerId":"%s-id"}}`, name, baseURL, name)
}

func TestLoginRouterHost(t *testing.T) {
	acme := installationJSON("acme", "https://api.acme.nullify.ai")
	beta := installationJSON("beta", "https://api.beta.nullify.ai")
	pending := `{"name":"pending","avatarUrl":"","provider":{},"queryParameters":{"githubOwnerId":"9"}}`

	tests := []struct {
		name          string
		host          string
		picker        InstallationPicker
		installations []string
		wantErr       string
		wantCreds     HostCredentials
	}{
		{
			name:          "single installation",
			host:          "nullify.ai",
			installations: []string{acme, pending},
			wantCreds: HostCredentials{
				AccessToken:     "access",
				RefreshToken:    "refresh",
				DataHost:        "acme.nullify.ai",
				Installation:    "acme",
				QueryParameters: map[string]string{"githubOwnerId": "acme-id"},
			},
		},
		{
			name:          "api alias from the wizard",
			host:          "api.nullify.ai",
			picker:        InstallationPicker{Name: "beta"},
			installations: []string{acme, beta},
			wantCreds: HostCredentials{
				AccessToken:     "access",
				RefreshToken:    "refresh",
				DataHost:        "beta.nullify.ai",
				Installation:    "beta",
				QueryParameters: map[string]string{"githubOwnerId": "beta-id"},
			},
		},
		{
			name:          "no usable installation",
			host:          "nullify.ai",
			installations: []string{pending},
			wantErr:       "nullify auth login --host <instance>.nullify.ai",
		},
		{
			name:          "several installations without a terminal",
			host:          "nullify.ai",
			installations: []string{acme, beta},
			wantErr:       "pass --installation <name>",
		},
		{
			name:          "unknown installation name",
			host:          "app.nullify.ai",
			picker:        InstallationPicker{Name: "gamma"},
			installations: []string{acme, beta},
			wantErr:       `installation "gamma" not found`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &fakeLoginServer{installations: `{"installations":[` + strings.Join(tt.installations, ",") + `]}`}
			newAuthServer(t, server.handle(t))
			authHosts := recordAuthHosts(t)
			stubBrowser(t)
			require.NoError(t, SaveConfig(&Config{Host: "previous.nullify.ai"}))

			err := Login(context.Background(), tt.host, tt.picker)

			require.Equal(t, 1, server.installationsCalls)
			requireOnlyRouterHost(t, *authHosts, 3)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				_, credsErr := LoadCredentials()
				require.True(t, os.IsNotExist(credsErr), "credentials must not be written on a failed selection")
				cfg, cfgErr := LoadConfig()
				require.NoError(t, cfgErr)
				require.Equal(t, "previous.nullify.ai", cfg.Host)
				return
			}
			require.NoError(t, err)

			creds, err := LoadCredentials()
			require.NoError(t, err)
			require.Len(t, creds, 1)
			got := creds[RouterHost]
			require.InDelta(t, time.Now().Add(time.Hour).Unix(), got.ExpiresAt, 5)
			got.ExpiresAt = 0
			require.Equal(t, tt.wantCreds, got)

			cfg, err := LoadConfig()
			require.NoError(t, err)
			require.Equal(t, RouterHost, cfg.Host)
		})
	}
}

func TestLoginTenantHostSkipsInstallationDiscovery(t *testing.T) {
	server := &fakeLoginServer{}
	newAuthServer(t, server.handle(t))
	stubBrowser(t)

	require.NoError(t, Login(context.Background(), "acme.nullify.ai", InstallationPicker{}))

	require.Zero(t, server.installationsCalls)
	creds, err := LoadCredentials()
	require.NoError(t, err)
	got := creds["acme.nullify.ai"]
	require.Empty(t, got.DataHost)
	require.Equal(t, map[string]string{"fromToken": "1"}, got.QueryParameters)
	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, "acme.nullify.ai", cfg.Host)
}

func TestRefreshTokenKeepsRouterSelection(t *testing.T) {
	newAuthServer(t, refreshHandler)
	authHosts := recordAuthHosts(t)
	require.NoError(t, SaveHostCredentials(RouterHost, HostCredentials{
		AccessToken:     "old",
		RefreshToken:    "rt",
		ExpiresAt:       time.Now().Add(-time.Hour).Unix(),
		DataHost:        "acme.nullify.ai",
		Installation:    "acme",
		QueryParameters: map[string]string{"githubOwnerId": "7"},
	}))

	token, err := GetValidToken(context.Background(), "api.nullify.ai")
	require.NoError(t, err)
	require.Equal(t, "new-id-token", token)
	requireOnlyRouterHost(t, *authHosts, 1)

	creds, err := LoadCredentials()
	require.NoError(t, err)
	got := creds[RouterHost]
	require.Equal(t, "new-id-token", got.AccessToken)
	require.Equal(t, "rt", got.RefreshToken)
	require.Equal(t, "acme.nullify.ai", got.DataHost)
	require.Equal(t, "acme", got.Installation)
	require.Equal(t, map[string]string{"githubOwnerId": "7"}, got.QueryParameters)
}

func TestRefreshTokenTakesResponseQueryParametersWithoutDataHost(t *testing.T) {
	newAuthServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"accessToken":"new","expiresIn":60}`))
	})
	require.NoError(t, SaveHostCredentials("acme.nullify.ai", HostCredentials{
		AccessToken:     "old",
		RefreshToken:    "rt",
		QueryParameters: map[string]string{"githubOwnerId": "7"},
	}))

	_, err := ForceRefreshToken(context.Background(), "acme.nullify.ai")
	require.NoError(t, err)

	creds, err := LoadCredentials()
	require.NoError(t, err)
	require.Empty(t, creds["acme.nullify.ai"].QueryParameters)
}

func TestRefreshTokenRereadsCredentialsBeforeWriting(t *testing.T) {
	newAuthServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, SaveHostCredentials("other.nullify.ai", HostCredentials{AccessToken: "other"}))
		assert.NoError(t, updateHostCredentials(RouterHost, func(hostCreds HostCredentials) HostCredentials {
			hostCreds.DataHost = "beta.nullify.ai"
			hostCreds.Installation = "beta"
			return hostCreds
		}))
		refreshHandler(w, r)
	})
	require.NoError(t, SaveHostCredentials(RouterHost, HostCredentials{
		AccessToken:  "old",
		RefreshToken: "rt",
		DataHost:     "acme.nullify.ai",
		Installation: "acme",
	}))

	_, err := ForceRefreshToken(context.Background(), "app.nullify.ai")
	require.NoError(t, err)

	creds, err := LoadCredentials()
	require.NoError(t, err)
	require.Equal(t, "other", creds["other.nullify.ai"].AccessToken)
	require.Equal(t, "new-id-token", creds[RouterHost].AccessToken)
	require.Equal(t, "beta.nullify.ai", creds[RouterHost].DataHost)
	require.Equal(t, "beta", creds[RouterHost].Installation)
}

func TestDataHost(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	got, err := DataHost("acme.nullify.ai")
	require.NoError(t, err)
	require.Equal(t, "acme.nullify.ai", got)

	_, err = DataHost(RouterHost)
	require.ErrorIs(t, err, ErrNoDataHost)

	require.NoError(t, SaveHostCredentials(RouterHost, HostCredentials{AccessToken: "t"}))
	_, err = DataHost("api.nullify.ai")
	require.ErrorIs(t, err, ErrNoDataHost)

	require.NoError(t, SaveHostCredentials(RouterHost, HostCredentials{AccessToken: "t", DataHost: "acme.nullify.ai"}))
	got, err = DataHost("api.nullify.ai")
	require.NoError(t, err)
	require.Equal(t, "acme.nullify.ai", got)

	path, err := credentialsPath()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0600))
	_, err = DataHost(RouterHost)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNoDataHost)
}

func TestSwitchInstallation(t *testing.T) {
	server := &fakeLoginServer{installations: `{"installations":[` +
		installationJSON("acme", "https://api.acme.nullify.ai") + "," +
		installationJSON("beta", "https://api.beta.nullify.ai") + `]}`}
	newAuthServer(t, server.handle(t))
	authHosts := recordAuthHosts(t)
	require.NoError(t, SaveHostCredentials(RouterHost, HostCredentials{
		AccessToken:     "access",
		RefreshToken:    "refresh",
		ExpiresAt:       time.Now().Add(time.Hour).Unix(),
		DataHost:        "acme.nullify.ai",
		Installation:    "acme",
		QueryParameters: map[string]string{"githubOwnerId": "acme-id"},
	}))
	require.NoError(t, SaveConfig(&Config{Host: "other.nullify.ai"}))

	_, err := SwitchInstallation(context.Background(), "gamma")
	require.ErrorContains(t, err, `installation "gamma" not found`)
	creds, err := LoadCredentials()
	require.NoError(t, err)
	require.Equal(t, "acme", creds[RouterHost].Installation)

	install, err := SwitchInstallation(context.Background(), "beta")
	require.NoError(t, err)
	requireOnlyRouterHost(t, *authHosts, 2)
	require.Equal(t, "beta.nullify.ai", install.DataHost)

	creds, err = LoadCredentials()
	require.NoError(t, err)
	got := creds[RouterHost]
	require.Equal(t, "access", got.AccessToken)
	require.Equal(t, "beta.nullify.ai", got.DataHost)
	require.Equal(t, "beta", got.Installation)
	require.Equal(t, map[string]string{"githubOwnerId": "beta-id"}, got.QueryParameters)
	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, RouterHost, cfg.Host)
}

func TestSwitchInstallationRequiresRouterLogin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	_, err := SwitchInstallation(context.Background(), "acme")
	require.ErrorContains(t, err, "not authenticated")
}
