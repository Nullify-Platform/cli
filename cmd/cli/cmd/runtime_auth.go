package cmd

import (
	"context"
	"os"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/lib"
)

type commandAuthContext struct {
	Host        string
	Token       string
	QueryParams map[string]string
}

func resolveCommandAuth(ctx context.Context) (*commandAuthContext, error) {
	commandHost := resolveHost(ctx)

	token, err := lib.GetNullifyToken(ctx, commandHost, nullifyToken, githubToken)
	if err != nil {
		return nil, err
	}

	queryParams := map[string]string{}
	creds, err := auth.LoadCredentials()
	if err == nil {
		if hostCreds, ok := creds[auth.CredentialKey(commandHost)]; ok && hostCreds.QueryParameters != nil {
			for key, value := range hostCreds.QueryParameters {
				queryParams[key] = value
			}
		}
	}

	// NULLIFY_GITHUB_OWNER_ID env var provides the githubOwnerId query param
	// when using NULLIFY_TOKEN directly (no stored credentials).
	if ownerID := os.Getenv("NULLIFY_GITHUB_OWNER_ID"); ownerID != "" {
		if _, set := queryParams["githubOwnerId"]; !set {
			queryParams["githubOwnerId"] = ownerID
		}
	}

	return &commandAuthContext{
		Host:        commandHost,
		Token:       token,
		QueryParams: queryParams,
	}, nil
}
