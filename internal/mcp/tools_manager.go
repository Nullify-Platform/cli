package mcp

import (
	"context"
	"net/url"

	"github.com/nullify-platform/cli/internal/api"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerManagerTools(s *server.MCPServer, c *api.Client) {
	s.AddTool(
		mcp.NewTool("list_campaigns",
			mcp.WithDescription("List remediation campaigns — coordinated efforts to fix groups of related findings."),
			mcp.WithNumber("limit", mcp.Description("Max results")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return wrap(c.ListManagerCampaigns(ctx, listParams(req)))
		},
	)

	s.AddTool(
		mcp.NewTool("get_campaign",
			mcp.WithDescription("Get a remediation campaign by ID, including progress and assigned findings."),
			mcp.WithString("campaign_id", mcp.Required(), mcp.Description("The campaign ID")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			p := url.Values{}
			p.Set("campaignId", getStringArg(req.GetArguments(), "campaign_id"))
			return wrap(c.GetManagerCampaignsCampaignId(ctx, p))
		},
	)

	s.AddTool(
		mcp.NewTool("list_escalations",
			mcp.WithDescription("List current escalations — findings flagged for urgent attention."),
			mcp.WithNumber("limit", mcp.Description("Max results")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return wrap(c.ListManagerEscalations(ctx, listParams(req)))
		},
	)
}
