package cmd

import (
	"context"
	"errors"
	"os"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/terminal"
)

func stdinIsTTY() bool {
	return terminal.IsInteractive(os.Stdin)
}

type commandAuthContext struct {
	Host        string
	Token       string
	QueryParams map[string]string
	// Org is the org the command runs as, nil when the server takes it from
	// an API token or it was given only as an id.
	Org *auth.Org
}

// Client builds a NullifyClient for the resolved host and token.
func (c *commandAuthContext) Client() *client.NullifyClient {
	return client.NewNullifyClient(c.Host, c.Token)
}

func (c *commandAuthContext) APIClient() *api.Client {
	return api.NewClient(c.Host, c.Token, c.QueryParams)
}

// resolveCommandAuth resolves the host, token and org a command runs with.
// Stored credentials no longer carry the org: a login's saved
// query_parameters were the server's default, not the user's choice.
func resolveCommandAuth(ctx context.Context) (*commandAuthContext, error) {
	authCtx, err := resolveCommandToken(ctx)
	if err != nil {
		return nil, err
	}

	scope, err := resolveOrgScope(ctx, authCtx.Host, authCtx.Token, orgInputsFor(authCtx.Host, orgFlag, "--org"), stdinIsTTY())
	if err != nil {
		return nil, authError("%w", err)
	}
	authCtx.Org = scope.Org
	authCtx.QueryParams = scope.Query
	return authCtx, nil
}

// resolveCommandToken resolves the host and token only, for callers that
// choose the org themselves.
func resolveCommandToken(ctx context.Context) (*commandAuthContext, error) {
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

	return &commandAuthContext{
		Host:        commandHost,
		Token:       token,
		QueryParams: map[string]string{},
	}, nil
}
