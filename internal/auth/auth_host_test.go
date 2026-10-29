package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	tenantHost = "acme.nullify.ai"
	tenantAPI  = "api.acme.nullify.ai"
	routerAPI  = "api.nullify.ai"
)

// hostCall is one request the routed auth server saw: the API host the CLI
// addressed and the path it asked for.
type hostCall struct{ host, path string }

// newRoutedAuthServer serves every auth host from one httptest server, with
// the addressed host as the first path segment, so a test can tell which
// host each call went to. It isolates the credential store like
// newAuthServer.
func newRoutedAuthServer(t *testing.T, h func(w http.ResponseWriter, r *http.Request, host, path string)) *[]hostCall {
	t.Helper()
	var (
		mu    sync.Mutex
		calls []hostCall
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, path, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		path = "/" + path
		mu.Lock()
		calls = append(calls, hostCall{host, path})
		mu.Unlock()
		h(w, r, host, path)
	}))
	oldBase, oldClient := authBaseURL, httpClient
	authBaseURL = func(host string) string { return srv.URL + "/" + apiHost(host) }
	httpClient = srv.Client()
	t.Cleanup(func() {
		authBaseURL, httpClient = oldBase, oldClient
		srv.Close()
	})
	t.Setenv("HOME", t.TempDir())
	return &calls
}

func authConfig(w http.ResponseWriter, authHost string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"auth_host": authHost})
}

func TestDiscoverAuthHost(t *testing.T) {
	tests := []struct {
		name    string
		handler func(w http.ResponseWriter)
		want    string
		wantErr string
	}{
		{"router", func(w http.ResponseWriter) { authConfig(w, "api.nullify.ai") }, routerAPI, ""},
		{"dev router", func(w http.ResponseWriter) { authConfig(w, "api.router.dev.nullify.ai") }, "api.router.dev.nullify.ai", ""},
		{"router with port 443 and case", func(w http.ResponseWriter) { authConfig(w, "API.Nullify.AI:443") }, routerAPI, ""},
		{"self", func(w http.ResponseWriter) { authConfig(w, tenantAPI) }, tenantAPI, ""},
		{"legacy stack without the endpoint", func(w http.ResponseWriter) { http.NotFound(w, nil) }, tenantAPI, ""},
		{"server error fails closed", func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }, "", "status 500"},
		{"forbidden fails closed", func(w http.ResponseWriter) { w.WriteHeader(http.StatusForbidden) }, "", "status 403"},
		{"foreign host fails closed", func(w http.ResponseWriter) { authConfig(w, "api.evil.example") }, "", "neither this tenant nor a Nullify router"},
		{"another tenant fails closed", func(w http.ResponseWriter) { authConfig(w, "api.other.nullify.ai") }, "", "neither this tenant nor a Nullify router"},
		{"router with another port fails closed", func(w http.ResponseWriter) { authConfig(w, "api.nullify.ai:8443") }, "", "neither this tenant nor a Nullify router"},
		{"empty answer fails closed", func(w http.ResponseWriter) { authConfig(w, "") }, "", "neither this tenant nor a Nullify router"},
		{"garbage body fails closed", func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>")) }, "", "decode auth config"},
		{"redirect fails closed", func(w http.ResponseWriter) {
			w.Header().Set("Location", "https://api.evil.example/auth/cli/config")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}, "", "status 307"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := newRoutedAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _, _ string) {
				tt.handler(w)
			})

			got, err := DiscoverAuthHost(context.Background(), tenantHost)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
				}
				if got != "" {
					t.Errorf("host = %q alongside an error, want none", got)
				}
			} else {
				if err != nil {
					t.Fatalf("DiscoverAuthHost: %v", err)
				}
				if got != tt.want {
					t.Errorf("auth host = %q, want %q", got, tt.want)
				}
			}
			if len(*calls) != 1 || (*calls)[0] != (hostCall{tenantAPI, "/auth/cli/config"}) {
				t.Errorf("calls = %v, want exactly one config lookup on the tenant", *calls)
			}
		})
	}
}

// fakeRouterLogin answers the tenant's config with the router and runs the
// session and redeem on the router. Anything else is a test failure.
func fakeRouterLogin(t *testing.T) func(w http.ResponseWriter, r *http.Request, host, path string) {
	return func(w http.ResponseWriter, r *http.Request, host, path string) {
		switch {
		case host == tenantAPI && path == "/auth/cli/config":
			authConfig(w, routerAPI)
		case host == routerAPI && path == "/auth/cli/session":
			var body struct{ Port int }
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(cliSessionResponse{
				SessionID: "sid",
				AuthURL:   "http://127.0.0.1:" + strconv.Itoa(body.Port) + "/callback?session_id=sid&redemption_secret=" + strings.Repeat("ab", 32),
			})
		case host == routerAPI && path == "/auth/cli/token":
			var body cliCallback
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.SessionID != "sid" || body.RedemptionSecret != strings.Repeat("ab", 32) {
				t.Errorf("redeem body = %+v, want the callback's session and secret", body)
			}
			_ = json.NewEncoder(w).Encode(cliTokenResponse{
				AccessToken:     "router-access",
				RefreshToken:    "router-refresh",
				ExpiresIn:       3600,
				QueryParameters: map[string]string{"githubOwnerId": "1"},
			})
		default:
			t.Errorf("unexpected call to %s%s", host, path)
			w.WriteHeader(http.StatusTeapot)
		}
	}
}

// The browser's job in a login is to hit the local callback; the test plays
// that part by fetching the auth URL the session returned.
func stubBrowser(t *testing.T) {
	t.Helper()
	old := openBrowser
	openBrowser = func(url string) error {
		go func() {
			resp, err := http.Get(url)
			if err != nil {
				t.Errorf("callback: %v", err)
				return
			}
			resp.Body.Close()
		}()
		return nil
	}
	t.Cleanup(func() { openBrowser = old })
}

func TestLoginRunsSessionAndRedeemOnTheAuthHost(t *testing.T) {
	calls := newRoutedAuthServer(t, fakeRouterLogin(t))
	stubBrowser(t)

	if err := Login(context.Background(), tenantHost); err != nil {
		t.Fatalf("Login: %v", err)
	}

	want := []hostCall{
		{tenantAPI, "/auth/cli/config"},
		{routerAPI, "/auth/cli/session"},
		{routerAPI, "/auth/cli/token"},
	}
	if len(*calls) != len(want) {
		t.Fatalf("calls = %v, want %v", *calls, want)
	}
	for i := range want {
		if (*calls)[i] != want[i] {
			t.Errorf("call %d = %v, want %v", i, (*calls)[i], want[i])
		}
	}

	creds, err := LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if _, ok := creds[CredentialKey(tenantHost)]; ok {
		t.Error("router login was stored under the tenant's own key")
	}
	if got := creds[CredentialKey(routerAPI)]; got.AccessToken != "router-access" || got.RefreshToken != "router-refresh" {
		t.Errorf("router credentials = %+v, want the redeemed tokens", got)
	}

	authHost, err := AuthHostFor(tenantHost)
	if err != nil || authHost != routerAPI {
		t.Errorf("AuthHostFor = %q, %v; want %q", authHost, err, routerAPI)
	}
	cfg, err := LoadConfig()
	if err != nil || cfg.Host != tenantHost {
		t.Errorf("config = %+v, %v; want host %q", cfg, err, tenantHost)
	}
}

func TestLoginFailsClosedWhenDiscoveryFails(t *testing.T) {
	calls := newRoutedAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _, _ string) {
		w.WriteHeader(http.StatusBadGateway)
	})
	stubBrowser(t)

	err := Login(context.Background(), tenantHost)
	if err == nil || !strings.Contains(err.Error(), "status 502") {
		t.Fatalf("err = %v, want the discovery failure", err)
	}
	if len(*calls) != 1 {
		t.Errorf("calls = %v, want only the config lookup: no session on any host", *calls)
	}
}

// bindRouter records a router login for the tenant, as Login would.
func bindRouter(t *testing.T, access string, expiresAt int64) {
	t.Helper()
	seed(t, routerAPI, access, "router-refresh", expiresAt)
	err := UpdateHostConfig(tenantHost, func(hc HostConfig) HostConfig {
		hc.AuthHost = routerAPI
		return hc
	})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
}

func routedRefresh(t *testing.T) func(w http.ResponseWriter, r *http.Request, host, path string) {
	return func(w http.ResponseWriter, r *http.Request, host, path string) {
		if path != "/auth/refresh_token" {
			t.Errorf("unexpected call to %s%s", host, path)
		}
		refreshHandler(w, r)
	}
}

func TestGetValidTokenRefreshesAtTheAuthHost(t *testing.T) {
	calls := newRoutedAuthServer(t, routedRefresh(t))
	bindRouter(t, "expired", time.Now().Add(-time.Hour).Unix())

	got, err := GetValidToken(context.Background(), tenantHost)
	if err != nil {
		t.Fatalf("GetValidToken: %v", err)
	}
	if got != "new-id-token" {
		t.Errorf("token = %q, want new-id-token", got)
	}
	if len(*calls) != 1 || (*calls)[0].host != routerAPI {
		t.Errorf("calls = %v, want one refresh on %s", *calls, routerAPI)
	}

	creds, _ := LoadCredentials()
	if creds[CredentialKey(routerAPI)].AccessToken != "new-id-token" {
		t.Error("refreshed token was not saved under the router's key")
	}
	if _, ok := creds[CredentialKey(tenantHost)]; ok {
		t.Error("refresh wrote a credential under the tenant's own key")
	}
}

func TestForceRefreshTokenRefreshesAtTheAuthHost(t *testing.T) {
	calls := newRoutedAuthServer(t, routedRefresh(t))
	bindRouter(t, "rejected", time.Now().Add(time.Hour).Unix())

	got, err := ForceRefreshToken(context.Background(), tenantHost)
	if err != nil {
		t.Fatalf("ForceRefreshToken: %v", err)
	}
	if got != "new-id-token" {
		t.Errorf("token = %q, want new-id-token", got)
	}
	if len(*calls) != 1 || (*calls)[0].host != routerAPI {
		t.Errorf("calls = %v, want one refresh on %s", *calls, routerAPI)
	}
}

// A credentials.json written before auth hosts existed has the tenant's
// login under the tenant's key and no hosts.json. It must keep working, and
// keep refreshing on the tenant.
func TestLegacyCredentialFileStillWorks(t *testing.T) {
	calls := newRoutedAuthServer(t, routedRefresh(t))
	dir := filepath.Join(os.Getenv("HOME"), ".nullify")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	legacy := `{"api.acme.nullify.ai": {"access_token": "legacy", "refresh_token": "legacy-rt", "expires_at": 1,` +
		` "query_parameters": {"githubOwnerId": "7"}}}`
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := GetValidToken(context.Background(), tenantHost)
	if err != nil {
		t.Fatalf("GetValidToken: %v", err)
	}
	if got != "new-id-token" {
		t.Errorf("token = %q, want the refreshed new-id-token", got)
	}
	if len(*calls) != 1 || (*calls)[0].host != tenantAPI {
		t.Errorf("calls = %v, want one refresh on the tenant itself", *calls)
	}

	hostCreds, authHost, ok, err := LookupCredentials(tenantHost)
	if err != nil || !ok {
		t.Fatalf("LookupCredentials: ok=%v err=%v", ok, err)
	}
	if CredentialKey(authHost) != CredentialKey(tenantHost) {
		t.Errorf("auth host = %q, want the tenant itself", authHost)
	}
	if hostCreds.QueryParameters["githubOwnerId"] != "7" {
		t.Errorf("legacy scope = %v, want it kept as stored", hostCreds.QueryParameters)
	}
}

func TestLogoutRemovesTheAuthHostLogin(t *testing.T) {
	newRoutedAuthServer(t, func(http.ResponseWriter, *http.Request, string, string) {})
	bindRouter(t, "live", time.Now().Add(time.Hour).Unix())
	seed(t, tenantHost, "legacy", "", 0)

	if err := Logout(tenantHost); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	creds, err := LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("credentials left after logout: %v", creds)
	}
	if _, err := GetValidToken(context.Background(), tenantHost); err == nil {
		t.Error("GetValidToken succeeded after logout")
	}
}

func TestKnownHostsListsTenantsNotTheRouter(t *testing.T) {
	newRoutedAuthServer(t, func(http.ResponseWriter, *http.Request, string, string) {})
	bindRouter(t, "live", time.Now().Add(time.Hour).Unix())
	seed(t, "legacy.nullify.ai", "tok", "", 0)

	got, err := KnownHosts()
	if err != nil {
		t.Fatalf("KnownHosts: %v", err)
	}
	want := []string{"acme.nullify.ai", "legacy.nullify.ai"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("KnownHosts = %v, want %v", got, want)
	}
}
