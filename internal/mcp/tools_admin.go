package mcp

import (
	"context"
	"time"

	"github.com/nullify-platform/cli/internal/client"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func metricsOverviewBody() map[string]any {
	return map[string]any{
		"query": map[string]any{
			"sort": []any{
				map[string]any{
					"isFalsePositive": map[string]any{
						"order":   "asc",
						"missing": 0,
					},
				},
			},
			"isArchived": false,
		},
	}
}

func metricsOverTimeBody(period string) map[string]any {
	now := time.Now().UTC()
	var from time.Time
	switch period {
	case "7d":
		from = now.AddDate(0, 0, -7)
	case "90d":
		from = now.AddDate(0, 0, -90)
	case "365d":
		from = now.AddDate(0, 0, -365)
	default: // 30d
		from = now.AddDate(0, 0, -30)
	}
	return map[string]any{
		"query": map[string]any{
			"sort": []any{
				map[string]any{
					"isFalsePositive": map[string]any{
						"order":   "asc",
						"missing": 0,
					},
				},
			},
			"isArchived": false,
			"fromDate":   from.Format(time.RFC3339),
			"toDate":     now.Format(time.RFC3339),
		},
	}
}

func registerAdminTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	s.AddTool(
		mcp.NewTool(
			"get_metrics_overview",
			mcp.WithDescription("Get a high-level security posture overview with counts of findings by severity and type. Use this to understand the overall security state."),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			qs := buildQueryString(queryParams)
			return doPost(ctx, c, "/admin/metrics/overview"+qs, metricsOverviewBody())
		},
	)

	s.AddTool(
		mcp.NewTool(
			"get_metrics_over_time",
			mcp.WithDescription("Get security metrics trends over time. Shows how the number of findings has changed, useful for tracking security posture improvements."),
			mcp.WithString("period", mcp.Description("Time period"), mcp.Enum("7d", "30d", "90d", "365d")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			period := getStringArg(args, "period")
			if period == "" {
				period = "30d"
			}
			qs := buildQueryString(queryParams)
			return doPost(ctx, c, "/admin/metrics/over-time"+qs, metricsOverTimeBody(period))
		},
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
