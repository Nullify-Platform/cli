package mcp

import (
	"github.com/nullify-platform/cli/internal/client"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerInfrastructureTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	s.AddTool(
		mcp.NewTool(
			"list_cloud_accounts",
			mcp.WithDescription("List connected cloud accounts (AWS, Azure, GCP) for infrastructure security monitoring."),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
		),
		makeGetHandler(c, "/graph/accounts", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"search_infrastructure",
			mcp.WithDescription("Search infrastructure nodes by name, type, or other attributes."),
			mcp.WithString("query", mcp.Required(), mcp.Description("Search query")),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
		),
		makeGetHandler(c, "/graph/nodes/search", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"get_infrastructure_graph",
			mcp.WithDescription("Get the full infrastructure graph showing relationships between cloud resources."),
		),
		makeGetHandler(c, "/graph/all", queryParams),
	)
}
