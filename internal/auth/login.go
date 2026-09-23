package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/nullify-platform/cli/internal/logger"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

// authBaseURL builds the API origin for the auth endpoints. It is a var so
// tests can point the auth calls at an httptest server.
var authBaseURL = func(host string) string { return "https://" + apiHost(host) }

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

func Login(ctx context.Context, host string) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start local server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	sessionResp, err := createCLISession(ctx, host, port)
	if err != nil {
		listener.Close()
		return fmt.Errorf("failed to create auth session: %w", err)
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

	if err := OpenBrowser(sessionResp.AuthURL); err != nil {
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
			return fmt.Errorf("local server error: %w", err)
		case <-ctx.Done():
			return fmt.Errorf("authentication cancelled")
		case <-timeout:
			return fmt.Errorf("authentication timed out — the session has expired")
		case <-ticker.C:
			fmt.Println("Still waiting for authentication...")
		}
	}

	tokenResp, err := fetchCLIToken(ctx, host, callback.SessionID, callback.RedemptionSecret)
	if err != nil {
		return fmt.Errorf("failed to fetch tokens: %w", err)
	}

	if tokenResp.Error != "" {
		return fmt.Errorf("authentication failed: %s", tokenResp.Error)
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Unix()

	err = SaveHostCredentials(host, HostCredentials{
		AccessToken:     tokenResp.AccessToken,
		RefreshToken:    tokenResp.RefreshToken,
		ExpiresAt:       expiresAt,
		QueryParameters: tokenResp.QueryParameters,
	})
	if err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	err = SaveConfig(&Config{Host: host})
	if err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println("\nAuthenticated successfully!")
	return nil
}

func Logout(host string) error {
	return DeleteHostCredentials(host)
}

func GetValidToken(ctx context.Context, host string) (string, error) {
	creds, err := LoadCredentials()
	if err != nil {
		return "", fmt.Errorf("not authenticated - run 'nullify auth login'")
	}

	key := CredentialKey(host)
	hostCreds, ok := creds[key]
	if !ok {
		return "", fmt.Errorf("not authenticated for %s - run 'nullify auth login --host %s'", host, host)
	}

	if hostCreds.ExpiresAt > 0 && time.Now().Unix() > hostCreds.ExpiresAt {
		if hostCreds.RefreshToken != "" {
			logger.L(ctx).Debug("access token expired, attempting refresh")
			refreshed, err := refreshToken(ctx, host, hostCreds.RefreshToken)
			if err != nil {
				return "", fmt.Errorf("token expired and refresh failed - run 'nullify auth login': %w", err)
			}
			return refreshed, nil
		}
		return "", fmt.Errorf("token expired - run 'nullify auth login'")
	}

	return hostCreds.AccessToken, nil
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
	creds, err := LoadCredentials()
	if err != nil {
		return "", fmt.Errorf("not authenticated - run 'nullify auth login'")
	}

	hostCreds, ok := creds[CredentialKey(host)]
	if !ok {
		return "", fmt.Errorf("not authenticated for %s - run 'nullify auth login --host %s'", host, host)
	}
	if hostCreds.RefreshToken == "" {
		return "", ErrNotRefreshable
	}

	logger.L(ctx).Debug("forcing access token refresh")
	return refreshToken(ctx, host, hostCreds.RefreshToken)
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

	resp, err := httpClient.Do(req)
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

	resp, err := httpClient.Do(req)
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

func refreshToken(ctx context.Context, host string, refreshTok string) (string, error) {
	refreshURL := authBaseURL(host) + "/auth/refresh_token"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, refreshURL, nil)
	if err != nil {
		return "", err
	}
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshTok})

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("refresh failed with status %d", resp.StatusCode)
	}

	var result struct {
		AccessToken     string            `json:"accessToken"`
		ExpiresIn       int               `json:"expiresIn"`
		QueryParameters map[string]string `json:"queryParameters"`
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

	err = SaveHostCredentials(host, HostCredentials{
		AccessToken:     result.AccessToken,
		RefreshToken:    refreshTok,
		ExpiresAt:       expiresAt,
		QueryParameters: result.QueryParameters,
	})
	if err != nil {
		logger.L(ctx).Warn("failed to save refreshed credentials", logger.Err(err))
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
