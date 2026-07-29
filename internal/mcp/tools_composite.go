package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nullify-platform/cli/internal/api"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// scannerLister returns a tiny list response for a single scanner. The
// composite tools fan out over these to assemble a multi-scanner overview;
// each closure adapts a typed list-findings method onto a uniform shape.
type scannerLister struct {
	name string
	// peek returns a JSON payload from the lister's list endpoint, limited to
	// one finding (used for "is this scanner producing findings?" probes).
	peek func(ctx context.Context, c *api.Client) (json.RawMessage, error)
}

// limitPtr returns a *int for the limit field on input structs.
func limitPtr(n int) *int {
	v := n
	return &v
}

var scannerListers = []scannerLister{
	{
		name: "sast",
		peek: func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
			return marshalOut(c.ListSastFindings(ctx, api.ListSastFindingsInput{Limit: limitPtr(1)}))
		},
	},
	{
		name: "sca_dependencies",
		peek: func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
			return marshalOut(c.ListScaDependenciesFindings(ctx, api.ListScaDependenciesFindingsInput{Limit: limitPtr(1)}))
		},
	},
	{
		name: "sca_containers",
		peek: func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
			return marshalOut(c.ListScaContainersFindings(ctx, api.ListScaContainersFindingsInput{Limit: limitPtr(1)}))
		},
	},
	{
		name: "secrets",
		peek: func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
			return marshalOut(c.ListSecretsFindings(ctx, api.ListSecretsFindingsInput{Limit: limitPtr(1)}))
		},
	},
	{
		name: "pentest",
		peek: func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
			return marshalOut(c.ListDastPentestFindings(ctx, api.ListDastPentestFindingsInput{Limit: limitPtr(1)}))
		},
	},
	{
		name: "bughunt",
		// bughunt's list endpoint doesn't accept a limit parameter (the spec
		// doesn't declare it); we just peek at whatever the default page
		// returns.
		peek: func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
			return marshalOut(c.ListDastBughuntFindings(ctx, api.ListDastBughuntFindingsInput{}))
		},
	},
	{
		name: "cspm",
		peek: func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
			return marshalOut(c.ListCspmFindings(ctx, api.ListCspmFindingsInput{Limit: limitPtr(1)}))
		},
	},
}

func registerCompositeTools(s *server.MCPServer, c *api.Client) {
	s.AddTool(
		mcp.NewTool("get_security_posture_summary",
			mcp.WithDescription("High-level security posture across all scanner types. Typically the first tool to call to understand overall state."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			type entry struct {
				Type  string          `json:"type"`
				Error string          `json:"error,omitempty"`
				Data  json.RawMessage `json:"data,omitempty"`
			}
			var out []entry
			for _, sc := range scannerListers {
				data, err := sc.peek(ctx, c)
				if err != nil {
					out = append(out, entry{Type: sc.name, Error: err.Error()})
					continue
				}
				out = append(out, entry{Type: sc.name, Data: data})
			}
			b, _ := json.MarshalIndent(out, "", "  ")
			return toolResult(string(b)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("get_findings_for_repo",
			mcp.WithDescription("Get findings for a specific repository across all scanner types."),
			mcp.WithString("repository", mcp.Required(), mcp.Description("Repository name")),
			mcp.WithString("severity", mcp.Description("Filter by severity"), mcp.Enum("critical", "high", "medium", "low")),
			mcp.WithNumber("limit", mcp.Description("Max results per scanner (default 20)")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			limit := getIntArg(args, "limit", 20)
			repo := getStringArg(args, "repository")
			severity := getStringArg(args, "severity")
			var parts []string
			// Fan out over the unified /admin/findings endpoint per type:
			// repository/severity are honored there (the per-scanner GET list
			// endpoints silently drop both).
			for _, sc := range scannerListers {
				findings, _, err := searchFindings(ctx, c, findingSearchOpts{
					apiTypes:   findingTypes[sc.name].apiTypes,
					severity:   severity,
					repository: repo,
					limit:      limit,
				})
				if err != nil {
					parts = append(parts, fmt.Sprintf("--- %s ---\nError: %v", sc.name, err))
					continue
				}
				b, _ := json.MarshalIndent(findings, "", "  ")
				parts = append(parts, fmt.Sprintf("--- %s ---\n%s", sc.name, string(b)))
			}
			return toolResult(strings.Join(parts, "\n\n")), nil
		},
	)

	s.AddTool(
		mcp.NewTool("get_critical_path",
			mcp.WithDescription("Get critical and high severity findings across all scanner types — the most urgent issues."),
			mcp.WithNumber("limit", mcp.Description("Max results per scanner per severity (default 10)")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			limit := getIntArg(req.GetArguments(), "limit", 10)
			var parts []string
			for _, sc := range scannerListers {
				apiTypes := findingTypes[sc.name].apiTypes
				for _, sev := range []string{"critical", "high"} {
					findings, _, err := searchFindings(ctx, c, findingSearchOpts{
						apiTypes: apiTypes,
						severity: sev,
						limit:    limit,
					})
					if err != nil || len(findings) == 0 {
						continue
					}
					b, _ := json.MarshalIndent(findings, "", "  ")
					parts = append(parts, fmt.Sprintf("--- %s (%s) ---\n%s", sc.name, sev, string(b)))
				}
			}
			if len(parts) == 0 {
				return toolResult("No critical or high severity findings found."), nil
			}
			return toolResult(strings.Join(parts, "\n\n")), nil
		},
	)

	s.AddTool(
		mcp.NewTool("get_security_trends",
			mcp.WithDescription("Security metrics: current posture overview plus how it has changed over time."),
			mcp.WithString("period", mcp.Description("Time period"), mcp.Enum("7d", "30d", "90d", "365d")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			period := getStringArg(req.GetArguments(), "period")
			if period == "" {
				period = "30d"
			}
			overview, err := c.CreateAdminMetricsOverview(ctx, metricsOverviewInput())
			if err != nil {
				return toolError(err), nil
			}
			overTime, err := c.CreateAdminMetricsOverTime(ctx, metricsOverTimeInput(period))
			if err != nil {
				return toolError(err), nil
			}
			ovBytes, _ := json.Marshal(overview)
			otBytes, _ := json.Marshal(overTime)
			return toolResult(fmt.Sprintf("--- Current Overview ---\n%s\n\n--- Trends (%s) ---\n%s", string(ovBytes), period, string(otBytes))), nil
		},
	)
}
