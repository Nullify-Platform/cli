package mcp

import (
	"context"
	"fmt"

	"github.com/nullify-platform/cli/internal/client"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerSCATools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	s.AddTool(
		mcp.NewTool(
			"list_sca_dependency_findings",
			mcp.WithDescription("List SCA (Software Composition Analysis) dependency findings - vulnerabilities in third-party libraries and packages. Includes CVE details, affected versions, and fix versions."),
			mcp.WithString("severity", mcp.Description("Filter by severity"), mcp.Enum("critical", "high", "medium", "low")),
			mcp.WithString("repository", mcp.Description("Filter by repository name")),
			mcp.WithString("status", mcp.Description("Filter by status"), mcp.Enum("open", "fixed", "false_positive")),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20, max 100)")),
		),
		makeGetHandler(c, "/sca/dependencies/findings", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"get_sca_dependency_finding",
			mcp.WithDescription("Get detailed information about a specific SCA dependency finding, including CVE details, affected package, and remediation steps."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The finding ID")),
		),
		makeGetByIDHandler(c, "/sca/dependencies/findings", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"list_sca_container_findings",
			mcp.WithDescription("List SCA container image findings - vulnerabilities in Docker/OCI container images. Includes base image and layer-level vulnerability details."),
			mcp.WithString("severity", mcp.Description("Filter by severity"), mcp.Enum("critical", "high", "medium", "low")),
			mcp.WithString("repository", mcp.Description("Filter by repository name")),
			mcp.WithString("status", mcp.Description("Filter by status"), mcp.Enum("open", "fixed", "false_positive")),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20, max 100)")),
		),
		makeGetHandler(c, "/sca/containers/findings", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"get_sca_container_finding",
			mcp.WithDescription("Get detailed information about a specific container image vulnerability finding."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The finding ID")),
		),
		makeGetByIDHandler(c, "/sca/containers/findings", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"triage_sca_dependency_finding",
			mcp.WithDescription("Update the triage status of an SCA dependency finding. Use this to mark findings as false positive, accepted risk, or to re-open them."),
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
			return doPut(c, fmt.Sprintf("/sca/dependencies/findings/%s/triage%s", id, qs), body)
		},
	)

	s.AddTool(
		mcp.NewTool(
			"triage_sca_container_finding",
			mcp.WithDescription("Update the triage status of an SCA container finding. Use this to mark findings as false positive, accepted risk, or to re-open them."),
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
			return doPut(c, fmt.Sprintf("/sca/containers/findings/%s/triage%s", id, qs), body)
		},
	)
}
