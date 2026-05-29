package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nullify-platform/cli/internal/api"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// scanRunLister adapts a typed scan-runs list method onto a uniform
// "(ctx, client, repoID, limit) → JSON" shape so the cross-scanner
// list-scan-runs tool can dispatch on the scanner type string.
type scanRunLister = func(ctx context.Context, c *api.Client, repoID string, limit int) (json.RawMessage, error)

var scanRunMethods = map[string]scanRunLister{
	"sast": func(ctx context.Context, c *api.Client, repoID string, limit int) (json.RawMessage, error) {
		in := api.ListSastScanRunsInput{}
		if limit > 0 {
			n := limit
			in.Limit = &n
		}
		return marshalOut(c.ListSastScanRuns(ctx, in))
	},
	"sca": func(ctx context.Context, c *api.Client, repoID string, limit int) (json.RawMessage, error) {
		in := api.ListScaScanRunsInput{}
		if limit > 0 {
			n := limit
			in.Limit = &n
		}
		return marshalOut(c.ListScaScanRuns(ctx, in))
	},
	"secrets": func(ctx context.Context, c *api.Client, repoID string, limit int) (json.RawMessage, error) {
		in := api.ListSecretsScanRunsInput{}
		if limit > 0 {
			n := limit
			in.Limit = &n
		}
		return marshalOut(c.ListSecretsScanRuns(ctx, in))
	},
}

func registerScanTools(s *server.MCPServer, c *api.Client) {
	s.AddTool(
		mcp.NewTool("nullify_start_cloud_scan",
			mcp.WithDescription("Start a cloud security scan (CSPM / cloud reconnaissance) for the authenticated installation. Returns a scanId; poll nullify_get_cloud_scan_status."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			out, err := c.CreateContextCloudScanStart(ctx, api.CreateContextCloudScanStartInput{})
			if err != nil {
				return toolError(err), nil
			}
			b, _ := json.Marshal(out)
			return toolResult(string(b)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("nullify_get_cloud_scan_status",
			mcp.WithDescription("Get the status of a cloud scan started with nullify_start_cloud_scan."),
			mcp.WithString("scan_id", mcp.Required(), mcp.Description("The scan ID")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			out, err := c.ListContextCloudScanScanIdStatus(ctx, api.ListContextCloudScanScanIdStatusInput{
				ScanID: getStringArg(req.GetArguments(), "scan_id"),
			})
			if err != nil {
				return toolError(err), nil
			}
			b, _ := json.Marshal(out)
			return toolResult(string(b)), nil
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
			lister, ok := scanRunMethods[getStringArg(args, "type")]
			if !ok {
				return toolError(fmt.Errorf("unknown scanner type %q. Valid: sast, sca, secrets", getStringArg(args, "type"))), nil
			}
			data, err := lister(ctx, c, getStringArg(args, "repository_id"), getIntArg(args, "limit", 0))
			if err != nil {
				return toolError(err), nil
			}
			return toolResult(string(data)), nil
		},
	)
}
