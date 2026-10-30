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

// commandAuthContext separates the host that issues tokens from the host that serves data.
type commandAuthContext struct {
	// AuthHost issues and refreshes the token: the router for a router
	// login, else the data host itself.
	AuthHost string
	// DataHost serves the command's requests.
	DataHost string
	// OnRouter is set when the command named the router rather than a
	// tenant, so an explicit org may move it to another tenant.
	OnRouter    bool
	Token       string
	QueryParams map[string]string
	// Org is the org the command runs as, nil when the server takes it from
	// an API token or it was given only as an id.
	Org *auth.Org
}

// Client builds a NullifyClient for the data host and token.
func (c *commandAuthContext) Client() *client.NullifyClient {
	return client.NewNullifyClient(c.DataHost, c.Token)
}

func (c *commandAuthContext) APIClient() *api.Client {
	return api.NewClient(c.DataHost, c.Token, c.QueryParams)
}

// coverTenant is auth.CoverTenant, a var so tests need no router.
var coverTenant = auth.CoverTenant

// resolveCommandAuth resolves the hosts, token and org a command runs with.
// Stored credentials no longer carry the org: a login's saved
// query_parameters were the server's default, not the user's choice.
func resolveCommandAuth(ctx context.Context) (*commandAuthContext, error) {
	authCtx, err := resolveCommandToken(ctx)
	if err != nil {
		return nil, err
	}

	in := orgInputsFor(authCtx.DataHost, orgFlag, "--org")
	in.AnyHost = authCtx.OnRouter
	scope, err := resolveOrgScope(ctx, authCtx.DataHost, authCtx.Token, in, stdinIsTTY())
	if err != nil {
		return nil, authError("%w", err)
	}
	if scope.Org != nil && scope.Org.DataHost() != "" && scope.Org.DataHost() != auth.CredentialKey(authCtx.DataHost) {
		authCtx.DataHost = scope.Org.DataHost()
	}
	if scope.Token != "" {
		authCtx.Token = scope.Token
	}
	authCtx.Org = scope.Org
	authCtx.QueryParams = scope.Query
	return authCtx, nil
}

// resolveCommandToken resolves the hosts and token only, for callers that
// choose the org themselves.
func resolveCommandToken(ctx context.Context) (*commandAuthContext, error) {
	authCtx, err := resolveCommandHosts(ctx)
	if err != nil {
		return nil, err
	}

	authCtx.Token, err = lib.GetNullifyToken(ctx, authCtx.AuthHost, nullifyToken, githubToken)
	if err != nil {
		if errors.Is(err, lib.ErrNoToken) {
			return nil, authError("not authenticated. Run 'nullify auth login' first")
		}
		return nil, authError("%w", err)
	}
	authCtx.QueryParams = map[string]string{}
	return authCtx, nil
}

// resolveCommandHosts sets the auth and data hosts for the command host.
func resolveCommandHosts(ctx context.Context) (*commandAuthContext, error) {
	commandHost, err := resolveHostE(ctx)
	if err != nil {
		return nil, err
	}
	return commandHostsFor(ctx, commandHost)
}

// commandHostsFor maps the host a command names to the host that signs it in
// and the host that serves it. The router serves sign-in only: its data host
// is the tenant of the selected org. A tenant signs in through the router it
// is bound to, through a router login that lists it, or by itself. An API or
// GitHub Actions token always goes to the tenant it names.
func commandHostsFor(ctx context.Context, commandHost string) (*commandAuthContext, error) {
	if router, ok := auth.RouterFor(commandHost); ok {
		if usesMachineToken() {
			return nil, authError("%s serves sign-in only - with --nullify-token or NULLIFY_TOKEN, set --host or NULLIFY_HOST to <instance>.nullify.ai", router.Key)
		}
		dataHost, err := auth.DataHost(router.Key)
		if err != nil {
			return nil, authError("%w", err)
		}
		// A CLI v0.26.0 login selected its data host without binding it.
		if err := auth.BindTenant(dataHost, router); err != nil {
			return nil, authError("%w", err)
		}
		return &commandAuthContext{AuthHost: router.Key, DataHost: dataHost, OnRouter: true}, nil
	}

	if usesMachineToken() {
		return &commandAuthContext{AuthHost: commandHost, DataHost: commandHost}, nil
	}

	if _, _, ok, err := auth.LookupCredentials(commandHost); err == nil && !ok {
		if _, err := coverTenant(ctx, commandHost); err != nil {
			return nil, authError("%w", err)
		}
	}
	authHost, err := auth.AuthHostFor(commandHost)
	if err != nil {
		return nil, authError("%w", err)
	}
	return &commandAuthContext{AuthHost: authHost, DataHost: commandHost}, nil
}
