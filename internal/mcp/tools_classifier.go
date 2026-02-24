package mcp

import (
	"github.com/nullify-platform/cli/internal/client"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerClassifierTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	s.AddTool(
		mcp.NewTool(
			"list_repositories",
			mcp.WithDescription("List repositories monitored by Nullify. Shows all connected code repositories with their classification and scanning status."),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
		),
		makeGetHandler(c, "/classifier/repositories", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"get_repository",
			mcp.WithDescription("Get detailed information about a specific monitored repository."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The repository ID")),
		),
		makeGetByIDHandler(c, "/classifier/repositories", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"list_applications",
			mcp.WithDescription("List applications classified by Nullify. Applications are logical groupings of repositories and services that form a product or system."),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
		),
		makeGetHandler(c, "/classifier/applications", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"get_application",
			mcp.WithDescription("Get detailed information about a specific application, including its associated repositories and dependencies."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The application ID")),
		),
		makeGetByIDHandler(c, "/classifier/applications", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"list_dependencies",
			mcp.WithDescription("List third-party dependencies across all monitored repositories. Useful for understanding your supply chain."),
			mcp.WithString("repository", mcp.Description("Filter by repository name")),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
		),
		makeGetHandler(c, "/classifier/dependencies", queryParams),
	)
}
