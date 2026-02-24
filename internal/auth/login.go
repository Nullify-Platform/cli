package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/nullify-platform/logger/pkg/logger"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type deviceTokenResponse struct {
	AccessToken     string            `json:"access_token,omitempty"`
	RefreshToken    string            `json:"refresh_token,omitempty"`
	ExpiresIn       int               `json:"expires_in,omitempty"`
	Error           string            `json:"error,omitempty"`
	QueryParameters map[string]string `json:"query_parameters,omitempty"`
}

type cliConfigResponse struct {
	DeviceAuthEnabled bool   `json:"device_auth_enabled"`
	VerificationURI   string `json:"verification_uri"`
	AppDomain         string `json:"app_domain"`
}

func DeviceFlowLogin(ctx context.Context, host string) error {
	// 1. Check CLI config endpoint
	cliConfig, err := getCLIConfig(ctx, host)
	if err != nil {
		logger.L(ctx).Debug("cli config endpoint not available, proceeding with defaults", logger.Err(err))
		cliConfig = &cliConfigResponse{
			DeviceAuthEnabled: true,
		}
	}

	if !cliConfig.DeviceAuthEnabled {
		return fmt.Errorf("device flow authentication is not enabled on this instance")
	}

	// 2. Request device code
	codeResp, err := requestDeviceCode(ctx, host)
	if err != nil {
		return fmt.Errorf("failed to request device code: %w", err)
	}

	// 3. Print instructions and open browser
	fmt.Printf("\nTo authenticate, visit:\n  %s\n\n", codeResp.VerificationURIComplete)
	fmt.Printf("And confirm the code: %s\n\n", codeResp.UserCode)
	fmt.Println("Waiting for authentication...")

	if err := openBrowser(codeResp.VerificationURIComplete); err != nil {
		logger.L(ctx).Debug("could not open browser automatically", logger.Err(err))
		fmt.Println("(Could not open browser automatically. Please open the URL above manually.)")
	}

	// 4. Poll for token
	interval := time.Duration(codeResp.Interval) * time.Second
	if interval == 0 {
		interval = 5 * time.Second
	}

	deadline := time.Now().Add(time.Duration(codeResp.ExpiresIn) * time.Second)

	for time.Now().Before(deadline) {
		time.Sleep(interval)

		tokenResp, err := pollDeviceToken(ctx, host, codeResp.DeviceCode)
		if err != nil {
			logger.L(ctx).Debug("poll error", logger.Err(err))
			continue
		}

		if tokenResp.Error == "authorization_pending" {
			continue
		}

		if tokenResp.Error == "slow_down" {
			interval += 5 * time.Second
			continue
		}

		if tokenResp.Error != "" {
			return fmt.Errorf("authentication failed: %s", tokenResp.Error)
		}

		// Success - store tokens
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

		// Save config with host
		err = SaveConfig(&Config{Host: host})
		if err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Println("\nAuthenticated successfully!")
		return nil
	}

	return fmt.Errorf("authentication timed out - the code has expired")
}

func Logout(host string) error {
	return DeleteHostCredentials(host)
}

func GetValidToken(ctx context.Context, host string) (string, error) {
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

func getCLIConfig(ctx context.Context, host string) (*cliConfigResponse, error) {
	url := fmt.Sprintf("https://%s/auth/cli_config", host)

	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cli_config returned status %d", resp.StatusCode)
	}

	var config cliConfigResponse
	err = json.NewDecoder(resp.Body).Decode(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func requestDeviceCode(ctx context.Context, host string) (*deviceCodeResponse, error) {
	url := fmt.Sprintf("https://%s/auth/device/code", host)

	resp, err := httpClient.Post(url, "application/json", strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device code request returned status %d", resp.StatusCode)
	}

	var codeResp deviceCodeResponse
	err = json.NewDecoder(resp.Body).Decode(&codeResp)
	if err != nil {
		return nil, err
	}

	return &codeResp, nil
}

func pollDeviceToken(ctx context.Context, host string, deviceCode string) (*deviceTokenResponse, error) {
	url := fmt.Sprintf("https://%s/auth/device/token", host)

	bodyData, err := json.Marshal(map[string]string{"device_code": deviceCode})
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Post(url, "application/json", strings.NewReader(string(bodyData)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("poll returned status %d", resp.StatusCode)
	}

	var tokenResp deviceTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	if err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

func refreshToken(ctx context.Context, host string, refreshTok string) (string, error) {
	url := fmt.Sprintf("https://%s/auth/refresh_token?refresh_token=%s", host, refreshTok)

	resp, err := httpClient.Get(url)
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

func openBrowser(url string) error {
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
