package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/mcp"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "MCP server for AI assistants",
	Long:  "Run Nullify as an MCP (Model Context Protocol) server for use with Claude Code, Cursor, and other AI tools.",
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server",
	Long: "Start the Nullify MCP server over stdio. Configure your AI tool to run 'nullify mcp serve'. " +
		"When your login covers several organizations on this instance, tools take an optional org argument. " +
		"The default for calls that name none is fixed when the server starts: --org, NULLIFY_ORG, " +
		"NULLIFY_GITHUB_OWNER_ID, the git remote's owner, then your default ('nullify org use'). One server serves one instance.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		repoFlag, _ := cmd.Flags().GetString("repo")
		toolsFlag, _ := cmd.Flags().GetString("tools")
		apiClient, toolSet, orgs, err := mcpServeConfig(ctx, repoFlag, toolsFlag)
		if err != nil {
			return err
		}

		if err := mcp.ServeWithClient(ctx, apiClient, toolSet, orgs); err != nil {
			return fmt.Errorf("MCP server error: %w", err)
		}
		return nil
	},
}

// mcpOrgCacheTTL is how long the server reuses its org list: every call
// needs it, and the router can be an ocean away from the data host.
var mcpOrgCacheTTL = 3 * time.Minute

type mcpOrgCache struct {
	mu    sync.Mutex
	list  auth.OrgList
	at    time.Time
	fetch func(ctx context.Context) (auth.OrgList, error)
}

func (c *mcpOrgCache) get(ctx context.Context, fresh bool) (auth.OrgList, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !fresh && !c.at.IsZero() && time.Since(c.at) < mcpOrgCacheTTL {
		return c.list, nil
	}
	list, err := c.fetch(ctx)
	if err != nil {
		return auth.OrgList{}, err
	}
	c.list, c.at = list, time.Now()
	return list, nil
}

func (c *mcpOrgCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = time.Time{}
}

// mcpDefault is the org a call naming none runs as, settled once from the
// inputs the server started with, so 'nullify org use' in a terminal never
// changes a running server. A failure to reach the org list is not settled.
type mcpDefault struct {
	mu      sync.Mutex
	settled bool
	org     *auth.Org
	query   map[string]string
	label   string
	err     error
}

// mcpServeConfig resolves the hosts and token, never an org: a login may
// cover several orgs, and each tool call picks one (its org argument, else
// the default the server started with).
func mcpServeConfig(ctx context.Context, repoFlag, toolsFlag string) (*api.Client, mcp.ToolSet, mcp.Orgs, error) {
	authCtx, err := resolveCommandToken(ctx)
	if err != nil {
		return nil, "", mcp.Orgs{}, err
	}
	dataHost := authCtx.DataHost

	queryParams := map[string]string{}
	if repo := resolveRepo(repoFlag); repo != "" {
		queryParams["repository"] = repo
	}

	toolSet := mcp.ToolSet(toolsFlag)
	if !slices.Contains(mcp.ValidToolSets(), toolsFlag) {
		return nil, "", mcp.Orgs{}, fmt.Errorf("invalid --tools value %q. Valid values: %s", toolsFlag, strings.Join(mcp.ValidToolSets(), ", "))
	}

	tokenProvider, refreshProvider := mcpTokenProviders(ctx, authCtx.AuthHost)

	listHost := dataHost
	if !usesMachineToken() {
		if listHost, err = auth.AuthHostFor(dataHost); err != nil {
			return nil, "", mcp.Orgs{}, err
		}
	}
	cache := &mcpOrgCache{fetch: func(ctx context.Context) (auth.OrgList, error) {
		token, err := tokenProvider()
		if err != nil {
			return auth.OrgList{}, err
		}
		list, _, err := listOrgsFresh(ctx, dataHost, listHost, token)
		return list, err
	}}

	// Drive the generated API client through a refreshing+retrying transport
	// so long-running MCP sessions keep working as the token rotates; the
	// token is refreshed wherever the login lives (the router, for a router
	// tenant). Each call's org scope is set by ScopeTransport.
	refreshing, err := client.NewRefreshingHTTPClient(dataHost, tokenProvider, refreshProvider)
	if err != nil {
		return nil, "", mcp.Orgs{}, fmt.Errorf("failed to create client: %w", err)
	}
	httpClient := &http.Client{
		Timeout:       refreshing.Timeout,
		Transport:     mcp.ScopeTransport(notHostedTransport{next: refreshing.Transport, refused: cache.invalidate}),
		CheckRedirect: refreshing.CheckRedirect,
	}
	// Empty token literal is intentional: the refreshing transport's
	// RoundTrip injects (and rotates) the Authorization header after
	// api.Client.do sets it, so the static value in api.Client is
	// overridden on every request.
	apiClient := api.NewClient(dataHost, "", queryParams, api.WithHTTPClient(httpClient))

	startInputs := orgInputsFor(dataHost, orgFlag, "--org")
	def := &mcpDefault{}
	resolveDefault := func(ctx context.Context) (*mcpDefault, error) {
		def.mu.Lock()
		defer def.mu.Unlock()
		if def.settled {
			return def, nil
		}
		token, err := tokenProvider()
		if err != nil {
			return nil, err
		}
		scope, err := resolveOrgScope(ctx, dataHost, token, startInputs, false)
		var notChosen *auth.ErrOrgNotChosen
		switch {
		case errors.As(err, &notChosen) && notChosen.Unavailable == nil:
			def.err = fmt.Errorf("%s serves several of your organizations and the server started without a default; "+
				"pass the org argument (name or id), or restart the server with --org: %s", dataHost, describeChoices(notChosen.Orgs))
		case err != nil && !isOrgDecision(err):
			return nil, err
		case err != nil:
			def.err = err
		default:
			def.org, def.query = scope.Org, scope.Query
			def.label = scopeLabel(scope)
		}
		def.settled = true
		return def, nil
	}

	orgs := mcp.Orgs{
		Resolve: func(ctx context.Context, org string) (map[string]string, string, error) {
			if org == "" {
				d, err := resolveDefault(ctx)
				if err != nil {
					return nil, "", err
				}
				if d.err != nil {
					return nil, "", d.err
				}
				return d.query, d.label, nil
			}
			in := auth.OrgInputs{Flag: org, FlagSource: "org argument"}
			if usesMachineToken() {
				token, err := tokenProvider()
				if err != nil {
					return nil, "", err
				}
				scope, err := resolveOrgScope(ctx, dataHost, token, in, false)
				if err != nil {
					return nil, "", err
				}
				return scope.Query, scopeLabel(scope), nil
			}
			list, err := cache.get(ctx, false)
			if err != nil {
				return nil, "", err
			}
			o, err := auth.ResolveOrg(dataHost, list, in)
			if err != nil {
				// The list may predate a new or moved org: look once more.
				if list, err = cache.get(ctx, true); err != nil {
					return nil, "", err
				}
				if o, err = auth.ResolveOrg(dataHost, list, in); err != nil {
					return nil, "", err
				}
			}
			return o.Query(), o.String(), nil
		},
		List: func(ctx context.Context) (any, error) {
			token, err := tokenProvider()
			if err != nil {
				return nil, err
			}
			out, err := orgListing(ctx, dataHost, token, startInputs)
			if err != nil {
				return nil, err
			}
			if d, err := resolveDefault(ctx); err == nil {
				out["selected"], out["selection"] = nil, nil
				if d.err != nil {
					out["selection"] = d.err.Error()
				} else {
					out["selected"] = d.label
					out["selection"] = "fixed when this server started"
				}
			}
			return out, nil
		},
	}

	return apiClient, toolSet, orgs, nil
}

func scopeLabel(scope orgScope) string {
	if scope.Org != nil {
		return scope.Org.String()
	}
	if id := scope.Query["githubOwnerId"]; id != "" {
		return "githubOwnerId " + id
	}
	return "the API token's own organization"
}

func describeChoices(orgs []auth.Org) string {
	choices := make([]string, len(orgs))
	for i, o := range orgs {
		choices[i] = o.String()
	}
	return strings.Join(choices, ", ")
}

// isOrgDecision reports whether err is an answer about the org (none, too
// many, not found, gone) rather than a failure to reach the org list.
func isOrgDecision(err error) bool {
	var notChosen *auth.ErrOrgNotChosen
	return errors.As(err, &notChosen) || errors.Is(err, auth.ErrNoOrgs) || errors.Is(err, auth.ErrOrgNotFound)
}

// notHostedTransport drops the server's cached org list when the data host
// says an org is not hosted there, so the next call sees where it moved. The
// refused request is returned as is, never replayed.
type notHostedTransport struct {
	next    http.RoundTripper
	refused func()
}

func (t notHostedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusForbidden {
		return resp, err
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if readErr == nil && bytes.Contains(body, []byte("is not hosted on this instance")) {
		t.refused()
	}
	return resp, nil
}

func init() {
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.AddCommand(mcpServeCmd)

	mcpServeCmd.Flags().String("repo", "", "Repository name to scope findings to (auto-detected from git remote if not set)")
	mcpServeCmd.Flags().String("tools", "default", "Tool set to register (default, all, minimal, findings, admin)")
}

func mcpTokenProviders(ctx context.Context, authHost string) (client.TokenProvider, client.TokenProvider) {
	tokenProvider := func() (string, error) {
		return lib.GetNullifyToken(ctx, authHost, nullifyToken, githubToken)
	}
	refreshProvider := func() (string, error) {
		return lib.RefreshNullifyToken(ctx, authHost, nullifyToken, githubToken)
	}
	return tokenProvider, refreshProvider
}

// resolveRepo determines the repository name from the flag or git config.
func resolveRepo(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}

	return lib.DetectRepoFromGit()
}
