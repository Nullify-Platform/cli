package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/nullify-platform/cli/internal/api"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// scanRunQuery holds the inputs of one scan-runs listing. The handlers of
// SAST, SCA and secrets require a repository, SCA also requires its scan type,
// and SCPM lists the whole tenant when the repository is empty.
type scanRunQuery struct {
	repositoryID string
	scanType     string
	limit        int
}

// scanRunLister adapts a typed scan-runs list method onto one shape, so that
// the cross-scanner list-scan-runs tool can dispatch on the scanner type.
type scanRunLister struct {
	needsRepository bool
	needsScanType   bool
	list            func(ctx context.Context, c *api.Client, q scanRunQuery) (json.RawMessage, error)
}

// scaScanTypes are the values that GET /sca/scan-runs accepts for scanType.
var scaScanTypes = []string{"sca_dependencies", "sca_containers"}

// scanRunScanners lists the scanner types in the order that help shows them.
var scanRunScanners = []string{"sast", "sca", "secrets", "scpm"}

var scanRunMethods = map[string]scanRunLister{
	"sast": {
		needsRepository: true,
		list: func(ctx context.Context, c *api.Client, q scanRunQuery) (json.RawMessage, error) {
			return marshalOut(c.ListSastScanRuns(ctx, api.ListSastScanRunsInput{
				RepositoryID: optionalString(q.repositoryID),
				Limit:        optionalLimit(q.limit),
			}))
		},
	},
	"sca": {
		needsRepository: true,
		needsScanType:   true,
		list: func(ctx context.Context, c *api.Client, q scanRunQuery) (json.RawMessage, error) {
			return marshalOut(c.ListScaScanRuns(ctx, api.ListScaScanRunsInput{
				RepositoryID: optionalString(q.repositoryID),
				ScanType:     optionalString(q.scanType),
				Limit:        optionalLimit(q.limit),
			}))
		},
	},
	"secrets": {
		needsRepository: true,
		list: func(ctx context.Context, c *api.Client, q scanRunQuery) (json.RawMessage, error) {
			return marshalOut(c.ListSecretsScanRuns(ctx, api.ListSecretsScanRunsInput{
				RepositoryID: optionalString(q.repositoryID),
				Limit:        optionalLimit(q.limit),
			}))
		},
	},
	"scpm": {
		list: func(ctx context.Context, c *api.Client, q scanRunQuery) (json.RawMessage, error) {
			return marshalOut(c.ListScpmScanRuns(ctx, api.ListScpmScanRunsInput{
				RepositoryID: optionalString(q.repositoryID),
				Limit:        optionalLimit(q.limit),
			}))
		},
	},
}

// check rejects a query that the scanner's handler would refuse, before any
// request is sent.
func (l scanRunLister) check(scanner string, q scanRunQuery) error {
	if l.needsRepository && q.repositoryID == "" {
		return fmt.Errorf("repository_id is required for %s scan runs", scanner)
	}
	if !l.needsScanType {
		if q.scanType != "" {
			return fmt.Errorf("scan_type applies only to sca scan runs, not %s", scanner)
		}
		return nil
	}
	if !slices.Contains(scaScanTypes, q.scanType) {
		return fmt.Errorf("scan_type must be one of %s for sca scan runs, got %q", strings.Join(scaScanTypes, ", "), q.scanType)
	}
	return nil
}

// optionalString returns nil for an empty value, so that the query leaves the
// parameter out.
func optionalString(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// optionalLimit returns nil for a limit that is not positive, so that the
// server applies its default.
func optionalLimit(n int) *int {
	if n <= 0 {
		return nil
	}
	return &n
}

func registerScanTools(s *server.MCPServer, c *api.Client) {
	s.AddTool(
		writeTool("nullify_start_cloud_scan",
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
		readOnlyTool("nullify_get_cloud_scan_status",
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
		readOnlyTool("nullify_list_scan_runs",
			mcp.WithDescription("List the scan run history of a scanner (SAST, SCA, secrets or SCPM) on a repository. Use list_repositories or get_repository to resolve a repository_id."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Scanner type"), mcp.Enum(scanRunScanners...)),
			mcp.WithString("repository_id", mcp.Description("Internal repository ID. It is required for sast, sca and secrets. For scpm, omit it to list the scan runs of every repository.")),
			mcp.WithString("scan_type", mcp.Description("The SCA scan type. It is required when type is sca and is refused for the other scanners."), mcp.Enum(scaScanTypes...)),
			mcp.WithNumber("limit", mcp.Description("Max results (the server default is 10 and its maximum is 50)")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			scanner := getStringArg(args, "type")
			lister, ok := scanRunMethods[scanner]
			if !ok {
				return toolError(fmt.Errorf("unknown scanner type %q. Valid: %s", scanner, strings.Join(scanRunScanners, ", "))), nil
			}
			q := scanRunQuery{
				repositoryID: getStringArg(args, "repository_id"),
				scanType:     getStringArg(args, "scan_type"),
				limit:        getIntArg(args, "limit", 0),
			}
			if err := lister.check(scanner, q); err != nil {
				return toolError(err), nil
			}
			return wrapRaw(lister.list(ctx, c, q))
		},
	)
}
