package client

import (
	"context"
	"strconv"

	"github.com/google/go-github/v64/github"
)

func GetGitHubID(ctx context.Context, githubOwner string) (string, error) {
	githubClient := github.NewClient(nil)
	user, _, err := githubClient.Users.Get(ctx, githubOwner)
	if err != nil {
		org, _, orgErr := githubClient.Organizations.Get(ctx, githubOwner)
		if orgErr != nil {
			return "", orgErr
		}
		return strconv.FormatInt(org.GetID(), 10), nil
	}

	return strconv.FormatInt(user.GetID(), 10), nil
}
