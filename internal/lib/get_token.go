package lib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/logger"
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
		os.Getenv("GITHUB_REPOSITORY") != "" {
		repo := os.Getenv("GITHUB_REPOSITORY")

		logger.L(ctx).Debug(
			"exchanging github actions token for a nullify token",
			logger.String("repository", repo),
		)

		parts := strings.Split(repo, "/")

		if len(parts) != 2 {
			return "", fmt.Errorf("invalid repository: %s", repo)
		}

		owner := parts[0]

		// Send the PAT in a POST body, never the URL, so it can't leak into
		// access logs or proxies. (The backend retains GET for older CLIs.)
		reqBody, err := json.Marshal(map[string]string{"owner": owner, "token": githubTokenFlag})
		if err != nil {
			return "", err
		}
		tokenURL := fmt.Sprintf("https://%s/auth/github_token", nullifyHost)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader(reqBody))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")

		httpClient := &http.Client{Timeout: 30 * time.Second}
		res, err := httpClient.Do(req)
		if err != nil {
			return "", err
		}
		defer res.Body.Close()

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
	storedToken, err := auth.GetValidToken(ctx, nullifyHost)
	if err == nil && storedToken != "" {
		logger.L(ctx).Debug("using token from stored credentials")
		return storedToken, nil
	}
	if err != nil {
		return "", fmt.Errorf("stored credentials: %w", err)
	}

	return "", ErrNoToken
}
