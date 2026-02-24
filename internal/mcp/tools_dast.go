package mcp

import (
	"context"
	"fmt"

	"github.com/nullify-platform/cli/internal/client"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerDASTTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	s.AddTool(
		mcp.NewTool(
			"list_dast_pentest_findings",
			mcp.WithDescription("List DAST (Dynamic Application Security Testing) pentest findings - vulnerabilities discovered by actively testing running applications and APIs."),
			mcp.WithString("severity", mcp.Description("Filter by severity"), mcp.Enum("critical", "high", "medium", "low")),
			mcp.WithString("status", mcp.Description("Filter by status"), mcp.Enum("open", "fixed", "false_positive")),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20, max 100)")),
		),
		makeGetHandler(c, "/dast/pentest/findings", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"get_dast_pentest_finding",
			mcp.WithDescription("Get detailed information about a specific DAST pentest finding."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The finding ID")),
		),
		makeGetByIDHandler(c, "/dast/pentest/findings", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"list_dast_bughunt_findings",
			mcp.WithDescription("List DAST Bug Hunt findings - vulnerabilities discovered through automated bug hunting of web applications."),
			mcp.WithString("severity", mcp.Description("Filter by severity"), mcp.Enum("critical", "high", "medium", "low")),
			mcp.WithString("status", mcp.Description("Filter by status"), mcp.Enum("open", "fixed", "false_positive")),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20, max 100)")),
		),
		makeGetHandler(c, "/dast/bughunt/findings", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"list_dast_pentest_scans",
			mcp.WithDescription("List DAST pentest scan history. Shows past and in-progress scans."),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
		),
		makeGetHandler(c, "/dast/pentest/scans", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"get_dast_pentest_scan",
			mcp.WithDescription("Get status and details of a specific DAST pentest scan."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The scan ID")),
		),
		makeGetByIDHandler(c, "/dast/pentest/scans", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"start_dast_pentest",
			mcp.WithDescription("Start a new DAST pentest scan against a target API. Requires an OpenAPI specification or target URL."),
			mcp.WithString("app_name", mcp.Required(), mcp.Description("Name of the application to scan")),
			mcp.WithString("target_host", mcp.Required(), mcp.Description("Base URL of the API to scan")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			body := map[string]string{
				"appName":    getStringArg(args, "app_name"),
				"targetHost": getStringArg(args, "target_host"),
			}
			qs := buildQueryString(queryParams)
			return doPost(c, fmt.Sprintf("/dast/pentest/start%s", qs), body)
		},
	)

	s.AddTool(
		mcp.NewTool(
			"triage_dast_finding",
			mcp.WithDescription("Update the triage status of a DAST finding. Use this to mark findings as false positive, accepted risk, or to re-open them."),
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
			return doPut(c, fmt.Sprintf("/dast/pentest/findings/%s/triage%s", id, qs), body)
		},
	)
}
