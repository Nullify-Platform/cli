package mcp

import (
	"context"
	"encoding/json"

	"github.com/nullify-platform/cli/internal/api"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// registerContextTools exposes repository/application inventory and SBOM
// retrieval. SBOM generate/resolve are pipeline-internal (need clone URL /
// commit SHA) and are intentionally left to `nullify api context`.
func registerContextTools(s *server.MCPServer, c *api.Client) {
	s.AddTool(
		mcp.NewTool("list_repositories",
			mcp.WithDescription("List repositories Nullify monitors for the authenticated installation."),
			mcp.WithNumber("limit", mcp.Description("Max results")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			in := api.ListContextRepositoriesInput{}
			if n := getIntArg(req.GetArguments(), "limit", 0); n > 0 {
				in.Limit = &n
			}
			return wrapTyped(c.ListContextRepositories(ctx, in))
		},
	)

	s.AddTool(
		mcp.NewTool("get_repository",
			mcp.WithDescription("Get a repository by its internal repository ID."),
			mcp.WithString("repository_id", mcp.Required(), mcp.Description("Internal repository ID")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return wrapTyped(c.GetContextRepositoriesRepositoryId(ctx, api.GetContextRepositoriesRepositoryIdInput{
				RepositoryID: getStringArg(req.GetArguments(), "repository_id"),
			}))
		},
	)

	s.AddTool(
		mcp.NewTool("list_applications",
			mcp.WithDescription("List applications (logical groupings of repositories) in the org."),
			mcp.WithNumber("limit", mcp.Description("Max results")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			// list_applications has no limit field on the spec input; the limit
			// arg is kept for compatibility with the prior tool shape but is
			// silently ignored — the endpoint returns the full set.
			_ = req
			return wrapTyped(c.ListContextApplications(ctx, api.ListContextApplicationsInput{}))
		},
	)

	s.AddTool(
		mcp.NewTool("get_application",
			mcp.WithDescription("Get an application by its ID."),
			mcp.WithString("application_id", mcp.Required(), mcp.Description("Application ID")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return wrapTyped(c.GetContextApplicationsApplicationId(ctx, api.GetContextApplicationsApplicationIdInput{
				ApplicationID: getStringArg(req.GetArguments(), "application_id"),
			}))
		},
	)

	s.AddTool(
		mcp.NewTool("get_latest_sbom",
			mcp.WithDescription("Get the latest CycloneDX SBOM for a repository."),
			mcp.WithString("repository_id", mcp.Required(), mcp.Description("Internal repository ID")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return wrapTyped(c.ListContextSbomsRepositoryRepositoryIdLatest(ctx, api.ListContextSbomsRepositoryRepositoryIdLatestInput{
				RepositoryID: getStringArg(req.GetArguments(), "repository_id"),
			}))
		},
	)

	s.AddTool(
		mcp.NewTool("get_sbom",
			mcp.WithDescription("Get the SBOM for a specific repository project."),
			mcp.WithString("repository_id", mcp.Required(), mcp.Description("Internal repository ID")),
			mcp.WithString("project_id", mcp.Required(), mcp.Description("Project ID within the repository")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			return wrapTyped(c.GetContextSbomsRepositoryRepositoryIdProjectProjectId(ctx, api.GetContextSbomsRepositoryRepositoryIdProjectProjectIdInput{
				RepositoryID: getStringArg(args, "repository_id"),
				ProjectID:    getStringArg(args, "project_id"),
			}))
		},
	)

	s.AddTool(
		mcp.NewTool("list_dependencies",
			mcp.WithDescription("List third-party dependencies across all monitored repositories. Useful for understanding the supply chain. Paginated via cursor."),
			mcp.WithNumber("pageSize", mcp.Description("Max results per page")),
			mcp.WithString("cursor", mcp.Description("Pagination cursor from a previous response")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			in := api.ListContextDepsInput{}
			if n := getIntArg(args, "pageSize", 0); n > 0 {
				ps := int32(n)
				in.PageSize = &ps
			}
			if cur := getStringArg(args, "cursor"); cur != "" {
				in.Cursor = &cur
			}
			return wrapTyped(c.ListContextDeps(ctx, in))
		},
	)

	s.AddTool(
		mcp.NewTool("get_dependency_exposure",
			mcp.WithDescription("Get exposure analysis for a specific dependency: which repositories use it and how (internet-facing vs internal)."),
			mcp.WithString("ecosystem", mcp.Required(), mcp.Description("Package ecosystem (e.g. npm, pypi, maven, go, nuget)")),
			mcp.WithString("name", mcp.Required(), mcp.Description("Dependency name to check exposure for")),
			mcp.WithString("range", mcp.Description("Version range filter (optional)")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			eco := getStringArg(args, "ecosystem")
			name := getStringArg(args, "name")
			in := api.ListContextDepsExposureInput{
				Ecosystem: &eco,
				Name:      &name,
			}
			if r := getStringArg(args, "range"); r != "" {
				in.Range = &r
			}
			return wrapTyped(c.ListContextDepsExposure(ctx, in))
		},
	)
}

// wrapTyped is a small adapter for tool handlers that call a typed method
// returning (*T, error): it marshals the response to JSON and wraps it as an
// MCP tool result. (The typed equivalent of the legacy wrap() helper.)
func wrapTyped[T any](out *T, err error) (*mcp.CallToolResult, error) {
	if err != nil {
		return toolError(err), nil
	}
	b, err := json.Marshal(out)
	if err != nil {
		return toolError(err), nil
	}
	return toolResult(string(b)), nil
}
