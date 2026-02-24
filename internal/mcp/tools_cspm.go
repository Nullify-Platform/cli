package mcp

import (
	"github.com/nullify-platform/cli/internal/client"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerCSPMTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	s.AddTool(
		mcp.NewTool(
			"list_cspm_findings",
			mcp.WithDescription("List CSPM (Cloud Security Posture Management) findings - misconfigurations and security issues in cloud infrastructure (AWS, Azure, GCP)."),
			mcp.WithString("severity", mcp.Description("Filter by severity"), mcp.Enum("critical", "high", "medium", "low")),
			mcp.WithString("status", mcp.Description("Filter by status"), mcp.Enum("open", "fixed", "false_positive")),
			mcp.WithString("account_id", mcp.Description("Filter by cloud account ID")),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20, max 100)")),
		),
		makeGetHandler(c, "/cspm/findings", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"get_cspm_finding",
			mcp.WithDescription("Get detailed information about a specific CSPM finding, including the misconfigured resource, compliance frameworks, and remediation steps."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The finding ID")),
		),
		makeGetByIDHandler(c, "/cspm/findings", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"list_cspm_scans",
			mcp.WithDescription("List CSPM scan history."),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
		),
		makeGetHandler(c, "/cspm/scans", queryParams),
	)
}
