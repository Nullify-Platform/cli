package lib

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

var ErrNoToken = errors.New("no token detected")

type githubToken struct {
	Token string `json:"accessToken"`
}

func GetNullifyToken(nullifyHost string, authSources *models.AuthSources) (string, error) {
	if authSources.NullifyToken != "" {
		logger.Debug("using token from config")
		return authSources.NullifyToken, nil
	}

	token := os.Getenv("NULLIFY_TOKEN")
	if token != "" {
		logger.Debug("using token from env")
		return token, nil
	}

	if os.Getenv("GITHUB_ACTIONS") == "true" &&
		authSources.GitHubToken != "" &&
		os.Getenv("GITHUB_ACTION_REPOSITORY") != "" {
		repo := os.Getenv("GITHUB_ACTION_REPOSITORY")

		logger.Debug(
			"exchanging github actions token for a nullify token",
			logger.String("repository", repo),
			logger.String("githubToken", authSources.GitHubToken),
		)

		parts := strings.Split(repo, "/")

		if len(parts) != 2 {
			return "", fmt.Errorf("invalid repository: %s", repo)
		}

		owner := parts[0]

		url := fmt.Sprintf("https://%s/auth/github_token?token=%s&owner=%s", nullifyHost, authSources.GitHubToken, owner)

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

		logger.Debug(
			"exchanged github actions token for a nullify token",
			logger.String("repository", repo),
			logger.String("token", token.Token),
		)

		return token.Token, nil
	}

	return "", ErrNoToken
}
