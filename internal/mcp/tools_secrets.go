package mcp

import (
	"context"
	"fmt"

	"github.com/nullify-platform/cli/internal/client"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerSecretsTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	s.AddTool(
		mcp.NewTool(
			"list_secrets_findings",
			mcp.WithDescription("List secrets findings - leaked credentials, API keys, tokens, and other sensitive data detected in code repositories."),
			mcp.WithString("severity", mcp.Description("Filter by severity"), mcp.Enum("critical", "high", "medium", "low")),
			mcp.WithString("repository", mcp.Description("Filter by repository name")),
			mcp.WithString("status", mcp.Description("Filter by status"), mcp.Enum("open", "fixed", "false_positive")),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20, max 100)")),
		),
		makeGetHandler(c, "/secrets/findings", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"get_secrets_finding",
			mcp.WithDescription("Get detailed information about a specific secrets finding, including the type of secret, location, and remediation guidance."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The finding ID")),
		),
		makeGetByIDHandler(c, "/secrets/findings", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"create_secrets_ticket",
			mcp.WithDescription("Create a Jira ticket for a secrets finding."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The finding ID")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			id := getStringArg(args, "id")
			qs := buildQueryString(queryParams)
			return doPost(c, fmt.Sprintf("/secrets/findings/%s/ticket%s", id, qs), nil)
		},
	)

	s.AddTool(
		mcp.NewTool(
			"get_secrets_finding_events",
			mcp.WithDescription("Get the event history for a secrets finding."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The finding ID")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			id := getStringArg(args, "id")
			qs := buildQueryString(queryParams)
			return doGet(c, fmt.Sprintf("/secrets/findings/%s/events%s", id, qs))
		},
	)

	s.AddTool(
		mcp.NewTool(
			"triage_secrets_finding",
			mcp.WithDescription("Update the triage status of a secrets finding. Use this to mark findings as false positive, accepted risk, or to re-open them."),
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
			return doPut(c, fmt.Sprintf("/secrets/findings/%s/triage%s", id, qs), body)
		},
	)
}
