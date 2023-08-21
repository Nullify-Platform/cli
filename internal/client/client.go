package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

type authTransport struct {
	token     string
	transport http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.transport.RoundTrip(req)
}

func NewHTTPClient(nullifyHost string, authSources *models.AuthSources) (*http.Client, error) {
	token, error := getToken(nullifyHost, authSources)
	if error != nil {
		return nil, error
	}

	return &http.Client{
		Transport: &authTransport{
			token:     token,
			transport: http.DefaultTransport,
		},
	}, nil
}

var ErrNoToken = errors.New("no token detected")

func getToken(nullifyHost string, authSources *models.AuthSources) (string, error) {
	if authSources.NullifyToken != "" {
		return authSources.NullifyToken, nil
	}

	token := os.Getenv("NULLIFY_TOKEN")
	if token != "" {
		return token, nil
	}

	if os.Getenv("GITHUB_ACTIONS") == "true" &&
		authSources.GitHubToken != "" &&
		os.Getenv("GITHUB_ACTION_REPOSITORY") != "" {
		repo := os.Getenv("GITHUB_ACTION_REPOSITORY")

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

		var token githubToken

		data, err := io.ReadAll(res.Body)
		if err != nil {
			return "", err
		}

		if err := json.Unmarshal(data, &token); err != nil {
			return "", err
		}

		logger.Info("raw github token", logger.String("data", string(data)))

		// err = json.NewDecoder(res.Body).Decode(&token)
		// if err != nil {
		// 	return "", err
		// }

		logger.Info("using github token", logger.String("token", token.Token))
		return token.Token, nil
	}

	return "", ErrNoToken
}
