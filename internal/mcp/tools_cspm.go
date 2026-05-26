package mcp

import (
	"context"

	"github.com/nullify-platform/cli/internal/api"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// registerCSPMTools registers CSPM scan tools. CSPM findings are reachable via
// the unified tools (type=cspm), so only scan history lives here.
func registerCSPMTools(s *server.MCPServer, c *api.Client) {
	s.AddTool(
		mcp.NewTool("list_cspm_scans",
			mcp.WithDescription("List CSPM (Cloud Security Posture Management) scan history."),
			mcp.WithNumber("limit", mcp.Description("Max results")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return wrap(c.ListCspmScans(ctx, listParams(req)))
		},
	)
}
