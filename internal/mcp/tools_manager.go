package mcp

import (
	"context"

	"github.com/nullify-platform/cli/internal/api"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerManagerTools(s *server.MCPServer, c *api.Client) {
	s.AddTool(
		readOnlyTool("list_campaigns",
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
		readOnlyTool("get_campaign",
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
		readOnlyTool("list_action_items",
			mcp.WithDescription("List action items: decisions and questions that need a person, ordered by priority."),
			mcp.WithNumber("limit", mcp.Description("Max results")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			in := api.ListManagerActionItemsInput{}
			if n := getIntArg(req.GetArguments(), "limit", 0); n > 0 {
				in.PageSize = &n
			}
			return wrapTyped(c.ListManagerActionItems(ctx, in))
		},
	)
}
