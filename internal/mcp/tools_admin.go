package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/nullify-platform/cli/internal/api"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func metricsOverviewBody() map[string]any {
	return map[string]any{
		"query": map[string]any{
			"sort":       []any{map[string]any{"isFalsePositive": map[string]any{"order": "asc", "missing": 0}}},
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
			"sort":       []any{map[string]any{"isFalsePositive": map[string]any{"order": "asc", "missing": 0}}},
			"isArchived": false,
			"fromDate":   from.Format(time.RFC3339),
			"toDate":     now.Format(time.RFC3339),
		},
	}
}

func jsonReader(v any) *bytes.Reader {
	data, _ := json.Marshal(v)
	return bytes.NewReader(data)
}

func registerAdminTools(s *server.MCPServer, c *api.Client) {
	s.AddTool(
		mcp.NewTool("get_metrics_overview",
			mcp.WithDescription("Get a high-level security posture overview: counts of findings by severity and type."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return wrap(c.CreateAdminMetricsOverview(ctx, nil, jsonReader(metricsOverviewBody())))
		},
	)

	s.AddTool(
		mcp.NewTool("get_metrics_over_time",
			mcp.WithDescription("Get security metrics trends over time."),
			mcp.WithString("period", mcp.Description("Time period"), mcp.Enum("7d", "30d", "90d", "365d")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			period := getStringArg(req.GetArguments(), "period")
			if period == "" {
				period = "30d"
			}
			return wrap(c.CreateAdminMetricsOverTime(ctx, nil, jsonReader(metricsOverTimeBody(period))))
		},
	)

	s.AddTool(
		mcp.NewTool("list_teams",
			mcp.WithDescription("List teams in the organization (used for assigning findings and access)."),
			mcp.WithNumber("limit", mcp.Description("Max results")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return wrap(c.ListAdminTeams(ctx, listParams(req)))
		},
	)

	s.AddTool(
		mcp.NewTool("list_sla_policies",
			mcp.WithDescription("List SLA policies defining expected remediation timeframes by severity."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return wrap(c.ListAdminSla(ctx, nil))
		},
	)

	s.AddTool(
		mcp.NewTool("get_organization",
			mcp.WithDescription("Get organization details including name, plan, and configuration."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return wrap(c.ListAdminOrganization(ctx, nil))
		},
	)
}
