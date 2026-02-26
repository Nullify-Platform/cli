package mcp

import (
	"github.com/nullify-platform/cli/internal/client"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerCodeReviewTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	s.AddTool(
		mcp.NewTool(
			"list_code_reviews",
			mcp.WithDescription("List code reviews performed by Nullify's AI agents on pull requests."),
			mcp.WithString("repository", mcp.Description("Filter by repository name")),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
		),
		makeGetHandler(c, "/orchestrator/codereviews", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"get_code_review",
			mcp.WithDescription("Get detailed information about a specific code review, including comments and findings."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The code review ID")),
		),
		makeGetByIDHandler(c, "/orchestrator/codereviews", queryParams),
	)
}
