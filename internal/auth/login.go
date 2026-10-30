package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/nullify-platform/cli/internal/logger"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

// authBaseURL builds the API origin for the auth endpoints. It is a var so
// tests can point the auth calls at an httptest server.
var authBaseURL = func(host string) string { return "https://" + apiHost(host) }

// authClient is httpClient without redirects. Session, redeem and refresh
// carry secrets, and a 307 would replay them to wherever it points.
func authClient() *http.Client {
	c := *httpClient
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

type cliSessionResponse struct {
	SessionID string `json:"session_id"`
	AuthURL   string `json:"auth_url"`
}

type cliTokenResponse struct {
	AccessToken     string            `json:"access_token,omitempty"`
	RefreshToken    string            `json:"refresh_token,omitempty"`
	ExpiresIn       int               `json:"expires_in,omitempty"`
	Error           string            `json:"error,omitempty"`
	QueryParameters map[string]string `json:"query_parameters,omitempty"`
}

// Login signs in for host in the browser. A router host signs in at that
// router. A tenant host is asked where its CLI login runs: a tenant on a
// router signs in at the router, which then covers every tenant it lists for
// the user, and picker chooses the org among those on host; any other
// tenant signs in itself.
func Login(ctx context.Context, host string, picker InstallationPicker) error {
	router, onRouter := RouterFor(host)
	tenant := ""
	authHost := router.AuthHost
	if !onRouter {
		discovered, err := DiscoverAuthHost(ctx, host)
		if err != nil {
			return fmt.Errorf("failed to find the login host: %w", err)
		}
		authHost = discovered
		router, onRouter = RouterFor(authHost)
		if onRouter {
			tenant = CredentialKey(host)
			fmt.Printf("%s signs in through %s.\n", host, authHost)
		}
	}

	tokenResp, err := browserLogin(ctx, authHost)
	if err != nil {
		return err
	}

	if onRouter {
		return saveRouterLogin(ctx, router, tenant, tokenResp, picker)
	}
	return saveTenantLogin(host, tokenResp)
}

func browserLogin(ctx context.Context, authHost string) (*cliTokenResponse, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to start local server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	sessionResp, err := createCLISession(ctx, authHost, port)
	if err != nil {
		listener.Close()
		return nil, fmt.Errorf("failed to create auth session: %w", err)
	}

	sessionCh := make(chan cliCallback, 1)
	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	mux.Handle("/callback", newLoginCallbackHandler(sessionResp.SessionID, sessionCh))

	server := &http.Server{Handler: mux}
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			errCh <- serveErr
		}
	}()
	defer server.Close()

	fmt.Printf("\nOpening browser to authenticate...\n")
	fmt.Printf("If the browser doesn't open, visit:\n  %s\n\n", sessionResp.AuthURL)

	if err := openBrowser(sessionResp.AuthURL); err != nil {
		logger.L(ctx).Debug("could not open browser automatically", logger.Err(err))
		fmt.Println("(Could not open browser automatically. Please open the URL above manually.)")
	}

	fmt.Println("Waiting for authentication... (press Ctrl+C to cancel)")

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	timeout := time.After(10 * time.Minute)

	var callback cliCallback
waitLoop:
	for {
		select {
		case callback = <-sessionCh:
			break waitLoop
		case err := <-errCh:
			return nil, fmt.Errorf("local server error: %w", err)
		case <-ctx.Done():
			return nil, fmt.Errorf("authentication cancelled")
		case <-timeout:
			return nil, fmt.Errorf("authentication timed out — the session has expired")
		case <-ticker.C:
			fmt.Println("Still waiting for authentication...")
		}
	}

	tokenResp, err := fetchCLIToken(ctx, authHost, callback.SessionID, callback.RedemptionSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tokens: %w", err)
	}
	if tokenResp.Error != "" {
		return nil, fmt.Errorf("authentication failed: %s", tokenResp.Error)
	}
	return tokenResp, nil
}

// saveTenantLogin stores a login a tenant ran itself. The query parameters it
// returned are the server's default org, kept only for older CLI versions
// reading this file; this version never takes them as the user's choice.
func saveTenantLogin(host string, tokenResp *cliTokenResponse) error {
	err := SaveHostCredentials(host, HostCredentials{
		AccessToken:     tokenResp.AccessToken,
		RefreshToken:    tokenResp.RefreshToken,
		ExpiresAt:       time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Unix(),
		QueryParameters: tokenResp.QueryParameters,
	})
	if err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	err = UpdateHostConfig(host, func(hc HostConfig) HostConfig {
		hc.AuthHost = apiHost(host)
		return hc
	})
	if err != nil {
		return fmt.Errorf("failed to save host config: %w", err)
	}

	if err := SaveConfig(&Config{Host: host}); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println("\nAuthenticated successfully!")
	return nil
}

// saveRouterLogin stores a router login and the org it starts with. Every
// tenant the router lists for the user is bound to the router, and a login a
// listed tenant ran itself before is removed: the router's covers it now.
// tenant, when set, limits the starting org to that tenant's. Nothing is
// saved when no org can be selected.
func saveRouterLogin(ctx context.Context, router Router, tenant string, tokenResp *cliTokenResponse, picker InstallationPicker) error {
	orgs, err := fetchOrgs(ctx, router.AuthHost, tokenResp.AccessToken)
	if err != nil {
		return err
	}
	routed := routedOrgs(orgs)

	choices := routed
	if tenant != "" {
		choices = orgsOn(routed, tenant)
	}
	if picker.Name == "" && picker.Remembered == nil {
		picker.Remembered = rememberedPick(router, tenant)
	}
	org, err := picker.Pick(choices)
	if err != nil {
		if tenant != "" {
			return fmt.Errorf("signed in through %s, but none of your organizations on %s can be used: %w", router.Key, tenant, err)
		}
		return err
	}

	hostCreds := withSelection(HostCredentials{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Unix(),
	}, org)

	tenants := map[string]bool{}
	for _, o := range routed {
		tenants[o.DataHost()] = true
	}

	err = updateCredentials(func(creds Credentials) Credentials {
		next := maps.Clone(creds)
		for t := range tenants {
			if t != router.Key {
				delete(next, t)
			}
		}
		next[router.Key] = hostCreds
		return next
	})
	if err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	err = updateHosts(func(hosts Hosts) Hosts {
		next := maps.Clone(hosts)
		for t := range tenants {
			hc := next[t]
			hc.AuthHost = router.AuthHost
			next[t] = hc
		}
		hc := next[org.DataHost()]
		hc.Org = pickOf(org)
		next[org.DataHost()] = hc
		return next
	})
	if err != nil {
		return fmt.Errorf("failed to save host config: %w", err)
	}

	if err := SaveConfig(&Config{Host: router.Key}); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Using %s on %s\n", org, org.DataHost())
	fmt.Println("\nAuthenticated successfully!")
	return nil
}

// rememberedPick is the org last chosen on tenant, or on the router's
// selected data host when no tenant is named.
func rememberedPick(router Router, tenant string) *OrgPick {
	if tenant == "" {
		creds, err := LoadCredentials()
		if err != nil {
			return nil
		}
		tenant = creds[router.Key].DataHost
		if tenant == "" {
			return nil
		}
	}
	hosts, err := LoadHosts()
	if err != nil {
		return nil
	}
	return hosts[CredentialKey(tenant)].Org
}

func pickOf(org Org) *OrgPick {
	return &OrgPick{Name: org.Name, Key: org.Key, ID: org.ID}
}

// withSelection records org as the router login's selected installation, in
// the fields CLI v0.26.0 reads too.
func withSelection(hostCreds HostCredentials, org Org) HostCredentials {
	hostCreds.DataHost = org.DataHost()
	hostCreds.Installation = org.Name
	hostCreds.QueryParameters = org.Query()
	return hostCreds
}

// SelectOrg makes org the default for its data host and, for a router login,
// moves the router's selected data host to it and makes the router the
// default host. Every way of choosing an org (the login picker, 'nullify org
// use', 'nullify auth switch --installation', the prompt) saves through here.
func SelectOrg(org Org) error {
	dataHost := org.DataHost()
	if dataHost == "" {
		return fmt.Errorf("%s is not served by a Nullify host yet", org.Name)
	}
	authHost, err := AuthHostFor(dataHost)
	if err != nil {
		return err
	}

	err = UpdateHostConfig(dataHost, func(hc HostConfig) HostConfig {
		hc.Org = pickOf(org)
		return hc
	})
	if err != nil {
		return fmt.Errorf("failed to save the organization: %w", err)
	}

	router, onRouter := RouterFor(authHost)
	if !onRouter {
		return nil
	}
	err = updateHostCredentials(router.Key, func(hostCreds HostCredentials) HostCredentials {
		return withSelection(hostCreds, org)
	})
	if err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}
	if err := SaveConfig(&Config{Host: router.Key}); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	return nil
}

// SwitchInstallation selects the named org among the router login's and makes the router the default host.
func SwitchInstallation(ctx context.Context, router Router, name string) (Org, error) {
	token, err := GetValidToken(ctx, router.Key)
	if err != nil {
		return Org{}, err
	}

	orgs, err := fetchOrgs(ctx, router.AuthHost, token)
	if err != nil {
		return Org{}, err
	}
	org, err := InstallationPicker{Name: name}.Pick(routedOrgs(orgs))
	if err != nil {
		return Org{}, err
	}
	if err := BindTenant(org.DataHost(), router); err != nil {
		return Org{}, err
	}
	return org, SelectOrg(org)
}

// BindTenant records that tenant signs in through router, unless it already does.
func BindTenant(tenant string, router Router) error {
	if authHost, err := AuthHostFor(tenant); err == nil && authHost == router.AuthHost {
		return nil
	}
	return UpdateHostConfig(tenant, func(hc HostConfig) HostConfig {
		hc.AuthHost = router.AuthHost
		return hc
	})
}

// DataHost returns the host that serves data for the credentials stored under authHost.
func DataHost(authHost string) (string, error) {
	router, onRouter := RouterFor(authHost)
	if !onRouter {
		return authHost, nil
	}

	creds, err := LoadCredentials()
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrNoDataHost
		}
		return "", fmt.Errorf("load credentials: %w", err)
	}
	dataHost := creds[router.Key].DataHost
	if dataHost == "" {
		return "", ErrNoDataHost
	}
	return dataHost, nil
}

// CheckSession returns an error unless host has a valid token and, for the router, a selected installation.
func CheckSession(ctx context.Context, host string) error {
	if _, err := GetValidToken(ctx, host); err != nil {
		return err
	}
	_, err := DataHost(host)
	return err
}

// Logout removes the credentials that serve host. On a router tenant those
// are the router login, shared with every other tenant signed in through it.
func Logout(host string) error {
	host = normalizeHost(host)
	authHost, err := AuthHostFor(host)
	if err != nil {
		return err
	}
	if err := DeleteHostCredentials(authHost); err != nil {
		return err
	}
	// A login from before the auth host was recorded sits under host itself.
	return DeleteHostCredentials(host)
}

// storedCredentials returns the credentials that serve the API host and the
// auth host that issued them, which is where they must be refreshed.
func storedCredentials(host string) (HostCredentials, string, error) {
	hostCreds, authHost, ok, err := LookupCredentials(normalizeHost(host))
	if errors.Is(err, os.ErrNotExist) {
		return HostCredentials{}, "", fmt.Errorf("not authenticated - run 'nullify auth login'")
	}
	if err != nil {
		return HostCredentials{}, "", fmt.Errorf("read stored credentials: %w", err)
	}
	if !ok {
		return HostCredentials{}, "", fmt.Errorf("not authenticated for %s - run 'nullify auth login --host %s'", host, host)
	}
	return hostCreds, authHost, nil
}

func GetValidToken(ctx context.Context, host string) (string, error) {
	hostCreds, _, err := storedCredentials(host)
	if err != nil {
		return "", err
	}
	if !expired(hostCreds) {
		return hostCreds.AccessToken, nil
	}
	return refreshOnce(ctx, host, false)
}

func expired(hostCreds HostCredentials) bool {
	return hostCreds.ExpiresAt > 0 && time.Now().Unix() > hostCreds.ExpiresAt
}

// ErrNotRefreshable reports that the stored credentials for a host carry no
// refresh token, so no amount of retrying will produce a new access token.
var ErrNotRefreshable = errors.New("no refresh token stored")

// ForceRefreshToken exchanges the stored refresh token for a new access token
// regardless of the recorded expiry. GetValidToken only refreshes once
// ExpiresAt has elapsed, which leaves callers no way to recover from a token
// the server rejects while the CLI still believes it is valid -- revocation, a
// killed session, or a local clock running behind the server's.
func ForceRefreshToken(ctx context.Context, host string) (string, error) {
	return refreshOnce(ctx, host, true)
}

// refreshReuse is how long a refresh answers every caller that was waiting on
// it, so concurrent calls rejected with the same token refresh once.
var refreshReuse = 30 * time.Second

type refreshState struct {
	mu sync.Mutex
	at time.Time
}

var refreshes sync.Map

// refreshOnce refreshes host's token at its auth host, one refresh at a time
// per auth host in this process.
func refreshOnce(ctx context.Context, host string, force bool) (string, error) {
	_, authHost, err := storedCredentials(host)
	if err != nil {
		return "", err
	}
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	v, _ := refreshes.LoadOrStore(dir+"|"+CredentialKey(authHost), &refreshState{})
	state := v.(*refreshState)
	state.mu.Lock()
	defer state.mu.Unlock()

	hostCreds, authHost, err := storedCredentials(host)
	if err != nil {
		return "", err
	}
	if !expired(hostCreds) && (!force || time.Since(state.at) < refreshReuse) {
		return hostCreds.AccessToken, nil
	}
	if hostCreds.RefreshToken == "" {
		if force {
			return "", ErrNotRefreshable
		}
		return "", fmt.Errorf("token expired - run 'nullify auth login'")
	}

	logger.L(ctx).Debug("refreshing access token", logger.String("authHost", authHost))
	token, err := refreshToken(ctx, authHost, hostCreds)
	if err != nil {
		if force {
			return "", err
		}
		return "", fmt.Errorf("token expired and refresh failed - run 'nullify auth login': %w", err)
	}
	state.at = time.Now()
	return token, nil
}

// routerAuthHost reports whether host is a router API host a tenant may hand
// its CLI login to. The CLI sends the user's login and refresh token wherever
// the tenant says, so any other answer is refused rather than followed.
func routerAuthHost(host string) bool {
	for _, r := range routers {
		if host == r.AuthHost {
			return true
		}
	}
	return false
}

// DiscoverAuthHost asks host where its CLI login runs (GET /auth/cli/config).
// A stack that predates the endpoint answers 404 and logs in on its own host.
// Any other failure, or an answer that is neither this tenant nor a known
// router, is an error: credentials never go to a host the CLI did not expect,
// and a failed discovery is never retried on another host.
func DiscoverAuthHost(ctx context.Context, host string) (string, error) {
	own := apiHost(host)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authBaseURL(host)+"/auth/cli/config", nil)
	if err != nil {
		return "", err
	}

	resp, err := authClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return own, nil
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("auth config request returned status %d: %s", resp.StatusCode, string(body))
	}

	var config struct {
		AuthHost string `json:"auth_host"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&config); err != nil {
		return "", fmt.Errorf("decode auth config: %w", err)
	}

	authHost := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(config.AuthHost)), ":443")
	switch {
	case strings.EqualFold(authHost, own):
		return own, nil
	case routerAuthHost(authHost):
		return authHost, nil
	default:
		return "", fmt.Errorf("%s names %q as its login host, which is neither this tenant nor a Nullify router", own, config.AuthHost)
	}
}

func createCLISession(ctx context.Context, host string, port int) (*cliSessionResponse, error) {
	url := authBaseURL(host) + "/auth/cli/session"

	bodyData, err := json.Marshal(map[string]int{"port": port})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(bodyData)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := authClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("session request returned status %d: %s", resp.StatusCode, string(body))
	}

	var sessionResp cliSessionResponse
	err = json.NewDecoder(resp.Body).Decode(&sessionResp)
	if err != nil {
		return nil, err
	}

	return &sessionResp, nil
}

func fetchCLIToken(ctx context.Context, host string, sessionID string, redemptionSecret string) (*cliTokenResponse, error) {
	url := authBaseURL(host) + "/auth/cli/token"

	bodyData, err := json.Marshal(cliCallback{SessionID: sessionID, RedemptionSecret: redemptionSecret})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(bodyData)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := authClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("token request returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp cliTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	if err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// errLoginReplaced reports that the login a refresh started from was removed
// or replaced while it ran, so its result must not be saved over the new one.
var errLoginReplaced = errors.New("the stored login changed during the refresh - run the command again")

// refreshToken exchanges stored's refresh token at authHost and saves the new
// access token over it. The org scope the server returns is not saved: it is
// the server's default (the lowest org id), not a choice the user made. The
// result is saved only if the stored login is still the one it started from.
func refreshToken(ctx context.Context, authHost string, stored HostCredentials) (string, error) {
	refreshURL := authBaseURL(authHost) + "/auth/refresh_token"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, refreshURL, nil)
	if err != nil {
		return "", err
	}
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: stored.RefreshToken})

	resp, err := authClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("refresh failed with status %d", resp.StatusCode)
	}

	var result struct {
		AccessToken string `json:"accessToken"`
		ExpiresIn   int    `json:"expiresIn"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	// The refresh endpoint returns its token in Set-Cookie, not the JSON body.
	if result.AccessToken == "" {
		for _, c := range resp.Cookies() {
			if c.Name != "access_token" || c.Value == "" {
				continue
			}
			result.AccessToken = c.Value
			if result.ExpiresIn == 0 {
				result.ExpiresIn = cookieLifetime(c)
			}
			break
		}
	}

	if result.AccessToken == "" {
		return "", fmt.Errorf("refresh returned empty access token")
	}

	expiresAt := time.Now().Add(time.Duration(result.ExpiresIn) * time.Second).Unix()
	replaced := false
	err = updateCredentials(func(creds Credentials) Credentials {
		current, ok := creds[CredentialKey(authHost)]
		if !ok || current.RefreshToken != stored.RefreshToken {
			replaced = true
			return creds
		}
		next := maps.Clone(creds)
		current.AccessToken = result.AccessToken
		current.ExpiresAt = expiresAt
		next[CredentialKey(authHost)] = current
		return next
	})
	if err != nil {
		logger.L(ctx).Warn("failed to save refreshed credentials", logger.Err(err))
	}
	if replaced {
		return "", errLoginReplaced
	}

	return result.AccessToken, nil
}

// cookieLifetime returns a cookie's remaining lifetime in seconds, preferring
// Max-Age and falling back to Expires. Returns 0 when the cookie carries
// neither, which refreshToken stores as an already-elapsed ExpiresAt: an
// unknown lifetime forces a refresh on next use rather than being trusted.
// Storing 0 instead would read as "never expires" in GetValidToken, which
// only checks an expiry it was actually given.
func cookieLifetime(c *http.Cookie) int {
	if c.MaxAge > 0 {
		return c.MaxAge
	}
	if !c.Expires.IsZero() {
		if secs := int(time.Until(c.Expires).Seconds()); secs > 0 {
			return secs
		}
	}
	return 0
}

// apiHost returns the API hostname, prepending "api." if not already present.
func apiHost(host string) string {
	if strings.HasPrefix(host, "api.") {
		return host
	}
	return "api." + host
}

// openBrowser is OpenBrowser, a var so tests can stand in for the user.
var openBrowser = OpenBrowser

// OpenBrowser opens the given URL in the user's default browser.
func OpenBrowser(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported platform")
	}

	return cmd.Start()
}
