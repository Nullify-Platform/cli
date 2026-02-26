package mcp

import (
	"github.com/nullify-platform/cli/internal/client"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerAdminTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	s.AddTool(
		mcp.NewTool(
			"get_metrics_overview",
			mcp.WithDescription("Get a high-level security posture overview with counts of findings by severity and type. Use this to understand the overall security state."),
		),
		makeGetHandler(c, "/admin/metrics/overview", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"get_metrics_over_time",
			mcp.WithDescription("Get security metrics trends over time. Shows how the number of findings has changed, useful for tracking security posture improvements."),
			mcp.WithString("period", mcp.Description("Time period"), mcp.Enum("7d", "30d", "90d", "365d")),
		),
		makeGetHandler(c, "/admin/metrics/over-time", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"get_global_config",
			mcp.WithDescription("Get the organization's global Nullify configuration, including scanning settings and integration configuration."),
		),
		makeGetHandler(c, "/admin/globalConfig", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"list_teams",
			mcp.WithDescription("List teams in the organization. Teams are used for assigning findings and managing access."),
			mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
		),
		makeGetHandler(c, "/admin/teams", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"list_sla_policies",
			mcp.WithDescription("List SLA (Service Level Agreement) policies that define expected remediation timeframes for findings by severity."),
		),
		makeGetHandler(c, "/admin/sla", queryParams),
	)

	s.AddTool(
		mcp.NewTool(
			"get_organization",
			mcp.WithDescription("Get organization details including name, plan, and configuration."),
		),
		makeGetHandler(c, "/admin/organization", queryParams),
	)
}
