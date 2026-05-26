package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/nullify-platform/cli/internal/api"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// scannerListers enumerates the per-scanner finding-list methods the
// cross-scanner composite tools fan out over.
var scannerListers = []struct {
	name string
	list methodNoBody
}{
	{"sast", (*api.Client).ListSastFindings},
	{"sca_dependencies", (*api.Client).ListScaDependenciesFindings},
	{"sca_containers", (*api.Client).ListScaContainersFindings},
	{"secrets", (*api.Client).ListSecretsFindings},
	{"pentest", (*api.Client).ListDastPentestFindings},
	{"bughunt", (*api.Client).ListDastBughuntFindings},
	{"cspm", (*api.Client).ListCspmFindings},
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
				p := url.Values{}
				p.Set("limit", "1")
				data, err := sc.list(c, ctx, p)
				if err != nil {
					out = append(out, entry{Type: sc.name, Error: err.Error()})
					continue
				}
				out = append(out, entry{Type: sc.name, Data: json.RawMessage(data)})
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
			var parts []string
			for _, sc := range scannerListers {
				p := url.Values{}
				p.Set("repository", getStringArg(args, "repository"))
				if sev := getStringArg(args, "severity"); sev != "" {
					p.Set("severity", sev)
				}
				p.Set("limit", fmt.Sprintf("%d", limit))
				data, err := sc.list(c, ctx, p)
				if err != nil {
					parts = append(parts, fmt.Sprintf("--- %s ---\nError: %v", sc.name, err))
					continue
				}
				parts = append(parts, fmt.Sprintf("--- %s ---\n%s", sc.name, string(data)))
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
				for _, sev := range []string{"critical", "high"} {
					p := url.Values{}
					p.Set("severity", sev)
					p.Set("limit", fmt.Sprintf("%d", limit))
					data, err := sc.list(c, ctx, p)
					if err != nil {
						continue
					}
					parts = append(parts, fmt.Sprintf("--- %s (%s) ---\n%s", sc.name, sev, string(data)))
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
			overview, err := c.CreateAdminMetricsOverview(ctx, nil, jsonReader(metricsOverviewBody()))
			if err != nil {
				return toolError(err), nil
			}
			overTime, err := c.CreateAdminMetricsOverTime(ctx, nil, jsonReader(metricsOverTimeBody(period)))
			if err != nil {
				return toolError(err), nil
			}
			return toolResult(fmt.Sprintf("--- Current Overview ---\n%s\n\n--- Trends (%s) ---\n%s", string(overview), period, string(overTime))), nil
		},
	)
}
