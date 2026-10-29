package mcp

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Orgs is how the server scopes each call to an organization. The server
// starts without one: a login can cover several orgs, and each tool call or
// resource read picks its own.
type Orgs struct {
	// Resolve returns the query parameters that scope one call. org is the
	// call's org argument, empty when it named none; Resolve then falls back
	// to serve --org and the CLI's usual chain, and errors with the choices
	// when that is still ambiguous.
	Resolve func(ctx context.Context, org string) (map[string]string, error)
	// List backs the list_organizations tool. Its result is returned as JSON.
	List func(ctx context.Context) (any, error)
}

const (
	orgArg                = "org"
	listOrganizationsTool = "list_organizations"
)

type scopeKey struct{}

func withScope(ctx context.Context, scope map[string]string) context.Context {
	return context.WithValue(ctx, scopeKey{}, scope)
}

// ScopeTransport sets the org scope a call resolved onto every request that
// call makes, over the client's default parameters. Scope travels in the
// request context, never in shared state, so concurrent calls for different
// orgs cannot cross.
func ScopeTransport(next http.RoundTripper) http.RoundTripper {
	return scopeTransport{next: next}
}

type scopeTransport struct{ next http.RoundTripper }

func (t scopeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	scope, _ := req.Context().Value(scopeKey{}).(map[string]string)
	if len(scope) == 0 {
		return t.next.RoundTrip(req)
	}
	r := req.Clone(req.Context())
	q := r.URL.Query()
	for k, v := range scope {
		q.Set(k, v)
	}
	r.URL.RawQuery = q.Encode()
	return t.next.RoundTrip(r)
}

// orgMiddleware resolves each tool call's org before the tool runs.
func orgMiddleware(orgs Orgs) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if req.Params.Name == listOrganizationsTool {
				return next(ctx, req)
			}
			scope, err := orgs.Resolve(ctx, getStringArg(req.GetArguments(), orgArg))
			if err != nil {
				return toolError(err), nil
			}
			return next(withScope(ctx, scope), req)
		}
	}
}

// resourceOrgMiddleware gives resource reads, which take no arguments, the
// same org rule as a tool call with no org argument.
func resourceOrgMiddleware(orgs Orgs) server.ResourceHandlerMiddleware {
	return func(next server.ResourceHandlerFunc) server.ResourceHandlerFunc {
		return func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			scope, err := orgs.Resolve(ctx, "")
			if err != nil {
				return nil, err
			}
			return next(withScope(ctx, scope), req)
		}
	}
}

// addOrgArgument adds the optional org argument to every registered tool.
func addOrgArgument(s *server.MCPServer) {
	tools := s.ListTools()
	updated := make([]server.ServerTool, 0, len(tools))
	for _, st := range tools {
		tool := st.Tool
		props := maps.Clone(tool.InputSchema.Properties)
		if props == nil {
			props = map[string]any{}
		}
		props[orgArg] = map[string]any{
			"type": "string",
			"description": "Organization to run as, by name or id. Needed only when your login covers several " +
				"organizations and no default is set; list_organizations shows them.",
		}
		tool.InputSchema.Properties = props
		if tool.InputSchema.Type == "" {
			tool.InputSchema.Type = "object"
		}
		updated = append(updated, server.ServerTool{Tool: tool, Handler: st.Handler})
	}
	s.SetTools(updated...)
}

func registerOrgTools(s *server.MCPServer, orgs Orgs) {
	s.AddTool(
		mcp.NewTool(listOrganizationsTool,
			mcp.WithDescription("List the organizations your Nullify login can use on this host, which one calls use by default, "+
				"and any not routed yet. Pass one as the org argument of another tool to run it as that organization."),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			out, err := orgs.List(ctx)
			if err != nil {
				return toolError(err), nil
			}
			data, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				return toolError(err), nil
			}
			return toolResult(string(data)), nil
		},
	)
}
