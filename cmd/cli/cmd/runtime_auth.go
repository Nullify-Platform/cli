package cmd

import (
	"context"
	"errors"
	"maps"
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

// commandAuthContext separates the host that issues tokens from the host that serves data.
type commandAuthContext struct {
	AuthHost    string
	DataHost    string
	Token       string
	QueryParams map[string]string
}

// Client builds a NullifyClient for the data host and token.
func (c *commandAuthContext) Client() *client.NullifyClient {
	return client.NewNullifyClient(c.DataHost, c.Token)
}

func (c *commandAuthContext) APIClient() *api.Client {
	return api.NewClient(c.DataHost, c.Token, c.QueryParams)
}

// resolveCommandHosts sets the auth and data hosts for the command host; only the router host has different ones.
func resolveCommandHosts(ctx context.Context) (*commandAuthContext, error) {
	commandHost, err := resolveHostE(ctx)
	if err != nil {
		return nil, err
	}
	return commandHostsFor(commandHost)
}

func commandHostsFor(commandHost string) (*commandAuthContext, error) {
	if !auth.IsRouterHost(commandHost) {
		return &commandAuthContext{AuthHost: commandHost, DataHost: commandHost}, nil
	}

	dataHost, err := auth.DataHost(auth.RouterHost)
	if errors.Is(err, auth.ErrNoDataHost) && explicitTokenSet() {
		return nil, authError("nullify.ai serves sign-in only - with --nullify-token or NULLIFY_TOKEN, set --host or NULLIFY_HOST to <instance>.nullify.ai")
	}
	if err != nil {
		return nil, authError("%w", err)
	}
	return &commandAuthContext{AuthHost: auth.RouterHost, DataHost: dataHost}, nil
}

func explicitTokenSet() bool {
	if nullifyToken != "" || os.Getenv("NULLIFY_TOKEN") != "" {
		return true
	}
	return os.Getenv("GITHUB_ACTIONS") == "true" && githubToken != "" && os.Getenv("GITHUB_REPOSITORY") != ""
}

// routerSignInHint returns a hint when tenantHost has no credentials but is the data host of the router sign-in.
func routerSignInHint(tenantHost string) string {
	creds, err := auth.LoadCredentials()
	if err != nil {
		return ""
	}
	if _, ok := creds[auth.CredentialKey(tenantHost)]; ok {
		return ""
	}
	if creds[auth.RouterHost].DataHost != tenantHost {
		return ""
	}
	return " (signed in through nullify.ai - use --host nullify.ai or 'nullify auth switch --host nullify.ai')"
}

func resolveCommandAuth(ctx context.Context) (*commandAuthContext, error) {
	authCtx, err := resolveCommandHosts(ctx)
	if err != nil {
		return nil, err
	}

	authCtx.Token, err = lib.GetNullifyToken(ctx, authCtx.AuthHost, nullifyToken, githubToken)
	if err != nil {
		if errors.Is(err, lib.ErrNoToken) {
			return nil, authError("not authenticated. Run 'nullify auth login' first")
		}
		if !auth.IsRouterHost(authCtx.AuthHost) {
			return nil, authError("%w%s", err, routerSignInHint(authCtx.AuthHost))
		}
		return nil, authError("%w", err)
	}

	queryParams := map[string]string{}
	creds, err := auth.LoadCredentials()
	if err == nil {
		maps.Copy(queryParams, creds[auth.CredentialKey(authCtx.AuthHost)].QueryParameters)
	}

	// NULLIFY_GITHUB_OWNER_ID env var provides the githubOwnerId query param
	// when using NULLIFY_TOKEN directly (no stored credentials).
	if ownerID := os.Getenv("NULLIFY_GITHUB_OWNER_ID"); ownerID != "" {
		if _, set := queryParams["githubOwnerId"]; !set {
			queryParams["githubOwnerId"] = ownerID
		}
	}

	authCtx.QueryParams = queryParams
	return authCtx, nil
}
