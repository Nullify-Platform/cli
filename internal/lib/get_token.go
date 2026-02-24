package lib

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/logger/pkg/logger"
)

var ErrNoToken = errors.New("no token detected")

type githubToken struct {
	Token string `json:"accessToken"`
}

func GetNullifyToken(
	ctx context.Context,
	nullifyHost string,
	nullifyTokenFlag string,
	githubTokenFlag string,
) (string, error) {
	// 1. Command-line flag
	if nullifyTokenFlag != "" {
		logger.L(ctx).Debug("using token from flag")
		return nullifyTokenFlag, nil
	}

	// 2. Environment variable
	token := os.Getenv("NULLIFY_TOKEN")
	if token != "" {
		logger.L(ctx).Debug("using token from env")
		return token, nil
	}

	// 3. GitHub Actions token exchange
	if os.Getenv("GITHUB_ACTIONS") == "true" &&
		githubTokenFlag != "" &&
		os.Getenv("GITHUB_ACTION_REPOSITORY") != "" {
		repo := os.Getenv("GITHUB_ACTION_REPOSITORY")

		logger.L(ctx).Debug(
			"exchanging github actions token for a nullify token",
			logger.String("repository", repo),
			logger.String("githubToken", githubTokenFlag),
		)

		parts := strings.Split(repo, "/")

		if len(parts) != 2 {
			return "", fmt.Errorf("invalid repository: %s", repo)
		}

		owner := parts[0]

		url := fmt.Sprintf("https://%s/auth/github_token?token=%s&owner=%s", nullifyHost, githubTokenFlag, owner)

		// nosec The URL is hardcoded and cannot be manipulated by an attacker
		res, err := http.Get(url)
		if err != nil {
			return "", err
		}

		if res.StatusCode != http.StatusOK {
			return "", client.HandleError(res)
		}

		var token githubToken
		err = json.NewDecoder(res.Body).Decode(&token)
		if err != nil {
			return "", err
		}

		logger.L(ctx).Debug(
			"exchanged github actions token for a nullify token",
			logger.String("repository", repo),
		)

		return token.Token, nil
	}

	// 4. Stored credentials from ~/.nullify/credentials.json
	storedToken, err := getStoredToken(ctx, nullifyHost)
	if err == nil && storedToken != "" {
		logger.L(ctx).Debug("using token from stored credentials")
		return storedToken, nil
	}

	return "", ErrNoToken
}

type storedCredentials struct {
	AccessToken     string            `json:"access_token"`
	RefreshToken    string            `json:"refresh_token"`
	ExpiresAt       int64             `json:"expires_at"`
	QueryParameters map[string]string `json:"query_parameters"`
}

func getStoredToken(ctx context.Context, nullifyHost string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	credPath := homeDir + "/.nullify/credentials.json"
	data, err := os.ReadFile(credPath)
	if err != nil {
		return "", err
	}

	var creds map[string]storedCredentials

	err = json.Unmarshal(data, &creds)
	if err != nil {
		return "", err
	}

	hostCreds, ok := creds[nullifyHost]
	if !ok {
		return "", fmt.Errorf("no credentials for host %s", nullifyHost)
	}

	if hostCreds.AccessToken == "" {
		return "", fmt.Errorf("no access token for host %s", nullifyHost)
	}

	// Check if token is expired
	if hostCreds.ExpiresAt > 0 && time.Now().Unix() > hostCreds.ExpiresAt {
		// Attempt refresh if we have a refresh token
		if hostCreds.RefreshToken != "" {
			logger.L(ctx).Debug("stored token expired, attempting refresh")
			return refreshStoredToken(ctx, nullifyHost, hostCreds.RefreshToken, credPath)
		}
		return "", fmt.Errorf("token expired for host %s - run 'nullify auth login'", nullifyHost)
	}

	return hostCreds.AccessToken, nil
}

func refreshStoredToken(ctx context.Context, host, refreshTok, credPath string) (string, error) {
	refreshURL := fmt.Sprintf("https://%s/auth/refresh_token?refresh_token=%s", host, refreshTok)

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Get(refreshURL)
	if err != nil {
		return "", fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token refresh failed with status %d", resp.StatusCode)
	}

	var result struct {
		AccessToken     string            `json:"accessToken"`
		ExpiresIn       int               `json:"expiresIn"`
		QueryParameters map[string]string `json:"queryParameters"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", fmt.Errorf("failed to decode refresh response: %w", err)
	}

	// Update stored credentials
	data, err := os.ReadFile(credPath)
	if err != nil {
		return result.AccessToken, nil // return token even if we can't save
	}

	var creds map[string]storedCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return result.AccessToken, nil
	}

	creds[host] = storedCredentials{
		AccessToken:     result.AccessToken,
		RefreshToken:    refreshTok,
		ExpiresAt:       time.Now().Add(time.Duration(result.ExpiresIn) * time.Second).Unix(),
		QueryParameters: result.QueryParameters,
	}

	updatedData, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return result.AccessToken, nil
	}

	_ = os.WriteFile(credPath, updatedData, 0600)

	return result.AccessToken, nil
}
