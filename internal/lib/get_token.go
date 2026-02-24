package lib

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/nullify-platform/cli/internal/auth"
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
	storedToken, err := auth.GetValidToken(ctx, nullifyHost)
	if err == nil && storedToken != "" {
		logger.L(ctx).Debug("using token from stored credentials")
		return storedToken, nil
	}

	return "", ErrNoToken
}
