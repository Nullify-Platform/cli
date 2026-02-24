package mcp

import (
	"github.com/nullify-platform/cli/internal/client"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerManagerTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	s.AddTool(
		mcp.NewTool(
			"list_campaigns",
			mcp.WithDescription("List active remediation campaigns. Campaigns are coordinated efforts to fix groups of related security findings."),
			mcp.WithString("status", mcp.Description("Filter by campaign status"), mcp.Enum("active", "completed", "paused")),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
		),
		makeGetHandler(c, "/manager/campaigns", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"get_campaign",
			mcp.WithDescription("Get detailed information about a specific remediation campaign, including progress and assigned findings."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The campaign ID")),
		),
		makeGetByIDHandler(c, "/manager/campaigns", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"list_escalations",
			mcp.WithDescription("List current escalations. Escalations are findings or issues that have been flagged for urgent attention."),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
		),
		makeGetHandler(c, "/manager/escalations", queryParams),
	)
}
