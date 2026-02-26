package mcp

import (
	"github.com/nullify-platform/cli/internal/client"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerBughuntTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	s.AddTool(
		mcp.NewTool(
			"list_bughunt_findings",
			mcp.WithDescription("List Bug Hunt findings - vulnerabilities discovered through automated bug hunting of web applications."),
			mcp.WithString("severity", mcp.Description("Filter by severity"), mcp.Enum("critical", "high", "medium", "low")),
			mcp.WithString("status", mcp.Description("Filter by status"), mcp.Enum("open", "fixed", "false_positive")),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20, max 100)")),
		),
		makeGetHandler(c, "/dast/bughunt/findings", queryParams),
	)
}
