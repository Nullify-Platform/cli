package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/nullify-platform/logger/pkg/logger/tracer"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

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

const successHTML = `<!DOCTYPE html>
<html><head><title>Nullify CLI</title>
<style>
body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5}
.card{text-align:center;padding:2rem;background:white;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,0.1);max-width:400px}
.check{width:48px;height:48px;margin:0 auto 1rem}
h1{color:#16a34a;font-size:1.5rem;margin:0 0 0.5rem}
p{color:#666;margin:0}
</style></head>
<body><div class="card">
<svg class="check" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
<h1>Authenticated Successfully!</h1>
<p>You can close this tab and return to your terminal.</p>
</div></body></html>`

func Login(ctx context.Context, host string) error {
	ctx, span := tracer.FromContext(ctx).Start(ctx, "auth.Login")
	defer span.End()

	// 1. Start localhost server on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start local server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	// 2. Create session on backend first so we know the expected session ID
	sessionResp, err := createCLISession(ctx, host, port)
	if err != nil {
		listener.Close()
		return fmt.Errorf("failed to create auth session: %w", err)
	}

	// 3. Set up callback handler that validates session ID
	sessionCh := make(chan string, 1)
	errCh := make(chan error, 1)
	var callbackOnce sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		receivedID := r.URL.Query().Get("session_id")

		// Verify the session ID matches what we requested (CSRF protection)
		if receivedID != sessionResp.SessionID {
			http.Error(w, "invalid session", http.StatusForbidden)
			return
		}

		// Only process the first valid callback (guard against duplicates)
		processed := false
		callbackOnce.Do(func() {
			processed = true
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, successHTML)
			sessionCh <- receivedID
		})
		if !processed {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, successHTML)
		}
	})

	server := &http.Server{Handler: mux}
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			errCh <- serveErr
		}
	}()
	defer server.Close()

	// 4. Open browser
	fmt.Printf("\nOpening browser to authenticate...\n")
	fmt.Printf("If the browser doesn't open, visit:\n  %s\n\n", sessionResp.AuthURL)

	if err := OpenBrowser(sessionResp.AuthURL); err != nil {
		logger.L(ctx).Debug("could not open browser automatically", logger.Err(err))
		fmt.Println("(Could not open browser automatically. Please open the URL above manually.)")
	}

	fmt.Println("Waiting for authentication... (press Ctrl+C to cancel)")

	// 5. Wait for callback with context cancellation support
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	var sessionID string
waitLoop:
	for {
		select {
		case sessionID = <-sessionCh:
			break waitLoop
		case err := <-errCh:
			return fmt.Errorf("local server error: %w", err)
		case <-ctx.Done():
			return fmt.Errorf("authentication cancelled")
		case <-time.After(10 * time.Minute):
			return fmt.Errorf("authentication timed out — the session has expired")
		case <-ticker.C:
			fmt.Println("Still waiting for authentication...")
		}
	}

	// 6. Fetch tokens from backend
	tokenResp, err := fetchCLIToken(ctx, host, sessionID)
	if err != nil {
		return fmt.Errorf("failed to fetch tokens: %w", err)
	}

	if tokenResp.Error != "" {
		return fmt.Errorf("authentication failed: %s", tokenResp.Error)
	}

	// 7. Store credentials
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
	ctx, span := tracer.FromContext(ctx).Start(ctx, "auth.GetValidToken")
	defer span.End()

	creds, err := LoadCredentials()
	if err != nil {
		return "", fmt.Errorf("not authenticated - run 'nullify auth login'")
	}

	hostCreds, ok := creds[host]
	if !ok {
		return "", fmt.Errorf("not authenticated for %s - run 'nullify auth login --host %s'", host, host)
	}

	// Check if token is expired and refresh if needed
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

func createCLISession(ctx context.Context, host string, port int) (*cliSessionResponse, error) {
	ctx, span := tracer.FromContext(ctx).Start(ctx, "auth.createCLISession")
	defer span.End()

	url := fmt.Sprintf("https://%s/auth/cli/session", apiHost(host))

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
		return nil, fmt.Errorf("session request returned status %d", resp.StatusCode)
	}

	var sessionResp cliSessionResponse
	err = json.NewDecoder(resp.Body).Decode(&sessionResp)
	if err != nil {
		return nil, err
	}

	return &sessionResp, nil
}

func fetchCLIToken(ctx context.Context, host string, sessionID string) (*cliTokenResponse, error) {
	ctx, span := tracer.FromContext(ctx).Start(ctx, "auth.fetchCLIToken")
	defer span.End()

	url := fmt.Sprintf("https://%s/auth/cli/token", apiHost(host))

	bodyData, err := json.Marshal(map[string]string{"session_id": sessionID})
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
		return nil, fmt.Errorf("token request returned status %d", resp.StatusCode)
	}

	var tokenResp cliTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	if err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

func refreshToken(ctx context.Context, host string, refreshTok string) (string, error) {
	ctx, span := tracer.FromContext(ctx).Start(ctx, "auth.refreshToken")
	defer span.End()

	refreshURL := fmt.Sprintf("https://%s/auth/refresh_token", apiHost(host))

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
