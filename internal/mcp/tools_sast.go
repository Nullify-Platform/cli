package mcp

import (
	"context"
	"fmt"

	"github.com/nullify-platform/cli/internal/client"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerSASTTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	s.AddTool(
		mcp.NewTool(
			"list_sast_findings",
			mcp.WithDescription("List SAST (Static Application Security Testing) findings - code vulnerabilities detected by static analysis. Returns issues like SQL injection, XSS, authentication bypasses, etc. Filter by severity to prioritize critical issues."),
			mcp.WithString("severity", mcp.Description("Filter by severity"), mcp.Enum("critical", "high", "medium", "low")),
			mcp.WithString("repository", mcp.Description("Filter by repository name")),
			mcp.WithString("status", mcp.Description("Filter by status"), mcp.Enum("open", "fixed", "false_positive")),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20, max 100)")),
		),
		makeGetHandler(c, "/sast/findings", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"get_sast_finding",
			mcp.WithDescription("Get detailed information about a specific SAST finding, including code location, vulnerability description, and remediation guidance."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The finding ID")),
		),
		makeGetByIDHandler(c, "/sast/findings", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"list_sast_repositories",
			mcp.WithDescription("List repositories monitored for SAST (static analysis) vulnerabilities."),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
		),
		makeGetHandler(c, "/sast/repositories", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"triage_sast_finding",
			mcp.WithDescription("Update the triage status of a SAST finding. Use this to mark findings as false positive, accepted risk, or to re-open them."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The finding ID")),
			mcp.WithString("status", mcp.Required(), mcp.Description("New triage status"), mcp.Enum("false_positive", "accepted_risk", "open")),
			mcp.WithString("reason", mcp.Description("Reason for the triage decision")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			id := getStringArg(args, "id")
			body := map[string]string{"status": getStringArg(args, "status")}
			if r := getStringArg(args, "reason"); r != "" {
				body["reason"] = r
			}
			qs := buildQueryString(queryParams)
			return doPut(c, fmt.Sprintf("/sast/findings/%s/triage%s", id, qs), body)
		},
	)

	s.AddTool(
		mcp.NewTool(
			"generate_sast_autofix",
			mcp.WithDescription("Generate an AI-powered autofix for a SAST finding. Returns a diff with the proposed code fix."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The finding ID")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			id := getStringArg(args, "id")
			qs := buildQueryString(queryParams)
			return doPost(c, fmt.Sprintf("/sast/findings/%s/autofix/fix%s", id, qs), nil)
		},
	)

	s.AddTool(
		mcp.NewTool(
			"get_sast_autofix_diff",
			mcp.WithDescription("Get the diff for a previously generated SAST autofix. Shows the proposed code changes."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The finding ID")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			id := getStringArg(args, "id")
			qs := buildQueryString(queryParams)
			return doGet(c, fmt.Sprintf("/sast/findings/%s/autofix/cache/diff%s", id, qs))
		},
	)
}
