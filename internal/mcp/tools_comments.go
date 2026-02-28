package mcp

import (
	"context"
	"fmt"

	"github.com/nullify-platform/cli/internal/client"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerCommentTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	s.AddTool(
		mcp.NewTool(
			"list_finding_comments",
			mcp.WithDescription("List comments on a specific finding. Comments can include discussion, triage notes, and remediation guidance."),
			mcp.WithString("finding_id", mcp.Required(), mcp.Description("The finding ID")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			findingID := getStringArg(args, "finding_id")
			qs := buildQueryString(queryParams)
			return doGet(ctx, c, fmt.Sprintf("/chat/comments/finding/%s%s", findingID, qs))
		},
	)

	s.AddTool(
		mcp.NewTool(
			"create_finding_comment",
			mcp.WithDescription("Add a comment to a finding. Use this to document triage decisions, ask questions, or provide remediation context."),
			mcp.WithString("finding_id", mcp.Required(), mcp.Description("The finding ID")),
			mcp.WithString("message", mcp.Required(), mcp.Description("The comment text")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			body := map[string]string{
				"findingId": getStringArg(args, "finding_id"),
				"message":   getStringArg(args, "message"),
			}
			qs := buildQueryString(queryParams)
			return doPost(ctx, c, fmt.Sprintf("/chat/comments%s", qs), body)
		},
	)
}
