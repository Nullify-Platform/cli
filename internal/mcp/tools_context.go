package mcp

import (
	"context"
	"fmt"
	"net/url"

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
			return wrap(c.ListContextRepositories(ctx, listParams(req)))
		},
	)

	s.AddTool(
		mcp.NewTool("get_repository",
			mcp.WithDescription("Get a repository by its internal repository ID."),
			mcp.WithString("repository_id", mcp.Required(), mcp.Description("Internal repository ID")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			p := url.Values{}
			p.Set("repositoryId", getStringArg(req.GetArguments(), "repository_id"))
			return wrap(c.GetContextRepositoriesRepositoryId(ctx, p))
		},
	)

	s.AddTool(
		mcp.NewTool("list_applications",
			mcp.WithDescription("List applications (logical groupings of repositories) in the org."),
			mcp.WithNumber("limit", mcp.Description("Max results")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return wrap(c.ListContextApplications(ctx, listParams(req)))
		},
	)

	s.AddTool(
		mcp.NewTool("get_application",
			mcp.WithDescription("Get an application by its ID."),
			mcp.WithString("application_id", mcp.Required(), mcp.Description("Application ID")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			p := url.Values{}
			p.Set("applicationId", getStringArg(req.GetArguments(), "application_id"))
			return wrap(c.GetContextApplicationsApplicationId(ctx, p))
		},
	)

	s.AddTool(
		mcp.NewTool("get_latest_sbom",
			mcp.WithDescription("Get the latest CycloneDX SBOM for a repository."),
			mcp.WithString("repository_id", mcp.Required(), mcp.Description("Internal repository ID")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			p := url.Values{}
			p.Set("repositoryId", getStringArg(req.GetArguments(), "repository_id"))
			return wrap(c.ListContextSbomsRepositoryRepositoryIdLatest(ctx, p))
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
			p := url.Values{}
			p.Set("repositoryId", getStringArg(args, "repository_id"))
			p.Set("projectId", getStringArg(args, "project_id"))
			return wrap(c.GetContextSbomsRepositoryRepositoryIdProjectProjectId(ctx, p))
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
			p := url.Values{}
			if n := getIntArg(args, "pageSize", 0); n > 0 {
				p.Set("pageSize", fmt.Sprintf("%d", n))
			}
			if cur := getStringArg(args, "cursor"); cur != "" {
				p.Set("cursor", cur)
			}
			return wrap(c.ListContextDeps(ctx, p))
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
			p := url.Values{}
			p.Set("ecosystem", getStringArg(args, "ecosystem"))
			p.Set("name", getStringArg(args, "name"))
			if r := getStringArg(args, "range"); r != "" {
				p.Set("range", r)
			}
			return wrap(c.ListContextDepsExposure(ctx, p))
		},
	)
}

// listParams builds url.Values for a list tool, forwarding an optional limit.
func listParams(req mcp.CallToolRequest) url.Values {
	p := url.Values{}
	if n := getIntArg(req.GetArguments(), "limit", 0); n > 0 {
		p.Set("limit", fmt.Sprintf("%d", n))
	}
	return p
}
