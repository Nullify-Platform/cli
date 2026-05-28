package mcp

import (
	"context"
	"fmt"
	"net/url"

	"github.com/nullify-platform/cli/internal/api"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// scanRunMethods maps a code-scanner type to its scan-runs list method. Code
// scanners are push/webhook driven and have no start endpoint; scan-runs
// exposes their history. (Cloud scans start here; pentest has its own tools.)
var scanRunMethods = map[string]methodNoBody{
	"sast":    (*api.Client).ListSastScanRuns,
	"sca":     (*api.Client).ListScaScanRuns,
	"secrets": (*api.Client).ListSecretsScanRuns,
}

func registerScanTools(s *server.MCPServer, c *api.Client) {
	s.AddTool(
		mcp.NewTool("nullify_start_cloud_scan",
			mcp.WithDescription("Start a cloud security scan (CSPM / cloud reconnaissance) for the authenticated installation. Returns a scanId; poll nullify_get_cloud_scan_status."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return wrap(c.CreateContextCloudScanStart(ctx, nil))
		},
	)

	s.AddTool(
		mcp.NewTool("nullify_get_cloud_scan_status",
			mcp.WithDescription("Get the status of a cloud scan started with nullify_start_cloud_scan."),
			mcp.WithString("scan_id", mcp.Required(), mcp.Description("The scan ID")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			p := url.Values{}
			p.Set("scanId", getStringArg(req.GetArguments(), "scan_id"))
			return wrap(c.ListContextCloudScanScanIdStatus(ctx, p))
		},
	)

	s.AddTool(
		mcp.NewTool("nullify_list_scan_runs",
			mcp.WithDescription("List scan run history for a code scanner (SAST, SCA, or secrets) on a repository. Use list_repositories / get_repository to resolve a repository_id."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Scanner type"), mcp.Enum("sast", "sca", "secrets")),
			mcp.WithString("repository_id", mcp.Required(), mcp.Description("Internal repository ID")),
			mcp.WithNumber("limit", mcp.Description("Max results")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			method, ok := scanRunMethods[getStringArg(args, "type")]
			if !ok {
				return toolError(fmt.Errorf("unknown scanner type %q. Valid: sast, sca, secrets", getStringArg(args, "type"))), nil
			}
			p := url.Values{}
			p.Set("repositoryId", getStringArg(args, "repository_id"))
			if n := getIntArg(args, "limit", 0); n > 0 {
				p.Set("limit", fmt.Sprintf("%d", n))
			}
			return wrap(method(c, ctx, p))
		},
	)
}
