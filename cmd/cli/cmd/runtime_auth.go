package cmd

import (
	"context"
	"errors"
	"os"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
)

// stdinIsTTY reports whether stdin is connected to an interactive terminal.
// Commands that prompt for input use this to fail fast in non-interactive
// environments (CI, pipes) instead of blocking forever on a read.
func stdinIsTTY() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

type commandAuthContext struct {
	Host        string
	Token       string
	QueryParams map[string]string
}

// Client builds a NullifyClient for the resolved host and token.
func (c *commandAuthContext) Client() *client.NullifyClient {
	return client.NewNullifyClient(c.Host, c.Token)
}

func resolveCommandAuth(ctx context.Context) (*commandAuthContext, error) {
	commandHost, err := resolveHostE(ctx)
	if err != nil {
		return nil, err
	}

	token, err := lib.GetNullifyToken(ctx, commandHost, nullifyToken, githubToken)
	if err != nil {
		if errors.Is(err, lib.ErrNoToken) {
			return nil, authError("not authenticated. Run 'nullify auth login' first")
		}
		return nil, authError("%w", err)
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
