package mcp

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/api/models"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// boolPtr is shared with the other tool files; defined here once.
func boolPtr(b bool) *bool { return &b }

// metricsSort matches the historical sort the legacy MCP tools used: surface
// non-false-positive findings first (missing=0 sorts nulls last). The
// generated query type has Sort []map[string]map[string]json.RawMessage; we
// build the equivalent payload by encoding the small sub-objects.
func metricsSort() []map[string]map[string]json.RawMessage {
	order, _ := json.Marshal("asc")
	missing, _ := json.Marshal(0)
	return []map[string]map[string]json.RawMessage{
		{"isFalsePositive": {"order": order, "missing": missing}},
	}
}

// metricsOverviewInput builds the typed input for CreateAdminMetricsOverview.
func metricsOverviewInput() api.CreateAdminMetricsOverviewInput {
	return api.CreateAdminMetricsOverviewInput{
		Query: models.ModelsUnifiedFindingsQuery{
			Sort:       metricsSort(),
			IsArchived: boolPtr(false),
		},
	}
}

// metricsOverTimeInput builds the typed input for CreateAdminMetricsOverTime
// covering the requested rolling window.
func metricsOverTimeInput(period string) api.CreateAdminMetricsOverTimeInput {
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
	fromStr := from.Format(time.RFC3339)
	toStr := now.Format(time.RFC3339)
	return api.CreateAdminMetricsOverTimeInput{
		Query: models.ModelsUnifiedFindingsQuery{
			Sort:       metricsSort(),
			IsArchived: boolPtr(false),
			FromDate:   &fromStr,
			ToDate:     &toStr,
		},
	}
}

func registerAdminTools(s *server.MCPServer, c *api.Client) {
	s.AddTool(
		mcp.NewTool("get_metrics_overview",
			mcp.WithDescription("Get a high-level security posture overview: counts of findings by severity and type."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			out, err := c.CreateAdminMetricsOverview(ctx, metricsOverviewInput())
			if err != nil {
				return toolError(err), nil
			}
			b, _ := json.Marshal(out)
			return toolResult(string(b)), nil
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
			out, err := c.CreateAdminMetricsOverTime(ctx, metricsOverTimeInput(period))
			if err != nil {
				return toolError(err), nil
			}
			b, _ := json.Marshal(out)
			return toolResult(string(b)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("list_teams",
			mcp.WithDescription("List teams in the organization (used for assigning findings and access)."),
			mcp.WithNumber("limit", mcp.Description("Max results")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			in := api.ListAdminTeamsInput{}
			if n := getIntArg(req.GetArguments(), "limit", 0); n > 0 {
				in.Limit = &n
			}
			out, err := c.ListAdminTeams(ctx, in)
			if err != nil {
				return toolError(err), nil
			}
			b, _ := json.Marshal(out)
			return toolResult(string(b)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("list_sla_policies",
			mcp.WithDescription("List SLA policies defining expected remediation timeframes by severity."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			out, err := c.ListAdminSla(ctx, api.ListAdminSlaInput{})
			if err != nil {
				return toolError(err), nil
			}
			b, _ := json.Marshal(out)
			return toolResult(string(b)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("get_organization",
			mcp.WithDescription("Get organization details including name and plan."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			out, err := c.ListAdminOrganization(ctx, api.ListAdminOrganizationInput{})
			if err != nil {
				return toolError(err), nil
			}
			b, _ := json.Marshal(out)
			return toolResult(string(b)), nil
		},
	)
}
