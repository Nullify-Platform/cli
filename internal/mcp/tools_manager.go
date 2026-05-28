package mcp

import (
	"context"

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
			in := api.ListManagerCampaignsInput{}
			if n := getIntArg(req.GetArguments(), "limit", 0); n > 0 {
				in.PageSize = &n
			}
			return wrapTyped(c.ListManagerCampaigns(ctx, in))
		},
	)

	s.AddTool(
		mcp.NewTool("get_campaign",
			mcp.WithDescription("Get a remediation campaign by ID, including progress and assigned findings."),
			mcp.WithString("campaign_id", mcp.Required(), mcp.Description("The campaign ID")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return wrapTyped(c.GetManagerCampaignsCampaignId(ctx, api.GetManagerCampaignsCampaignIdInput{
				CampaignID: getStringArg(req.GetArguments(), "campaign_id"),
			}))
		},
	)

	s.AddTool(
		mcp.NewTool("list_escalations",
			mcp.WithDescription("List current escalations — findings flagged for urgent attention."),
			mcp.WithNumber("limit", mcp.Description("Max results")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			in := api.ListManagerEscalationsInput{}
			if n := getIntArg(req.GetArguments(), "limit", 0); n > 0 {
				in.PageSize = &n
			}
			return wrapTyped(c.ListManagerEscalations(ctx, in))
		},
	)
}
