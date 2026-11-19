package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/findings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// scannerTypes are the finding types that the composite tools fan out over, in
// the order that they report them. Each is a key of findings.Types.
var scannerTypes = []string{"sast", "sca_dependencies", "sca_containers", "secrets", "pentest", "bughunt", "cspm", "scpm"}

// limitPtr returns a *int for the limit field on input structs.
func limitPtr(n int) *int {
	v := n
	return &v
}

func registerCompositeTools(s *server.MCPServer, c *api.Client, d Defaults) {
	registerPostureSummaryTool(s, c, d)

	s.AddTool(
		readOnlyTool("get_findings_for_repo",
			mcp.WithDescription("Get findings for a specific repository across all scanner types. "+findingsSearchScope),
			mcp.WithString("repository", mcp.Required(), mcp.Description(repositoryFilterHelp)),
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
			for _, name := range scannerTypes {
				apiTypes := findings.Types[name].APITypes
				if !findings.HasRepository(apiTypes) {
					parts = append(parts, fmt.Sprintf("--- %s ---\nNot listed: these findings have no repository.", name))
					continue
				}

				result, err := findings.Search(ctx, c, findings.SearchOptions{
					APITypes:   apiTypes,
					Severity:   severity,
					Repository: repo,
					Limit:      limit,
				})
				if err != nil {
					parts = append(parts, fmt.Sprintf("--- %s ---\nError: %v", name, err))
					continue
				}
				b, _ := json.MarshalIndent(result, "", "  ")
				parts = append(parts, fmt.Sprintf("--- %s ---\n%s", name, string(b)))
			}
			return toolResult(strings.Join(parts, "\n\n")), nil
		},
	)

	s.AddTool(
		readOnlyTool("get_critical_path",
			mcp.WithDescription("Get critical and high severity findings across all scanner types — the most urgent issues. "+findingsSearchScope),
			mcp.WithNumber("limit", mcp.Description("Max results per scanner per severity (default 10)")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			limit := getIntArg(req.GetArguments(), "limit", 10)
			var parts []string
			for _, name := range scannerTypes {
				apiTypes := findings.Types[name].APITypes
				for _, sev := range []string{"critical", "high"} {
					result, err := findings.Search(ctx, c, findings.SearchOptions{
						APITypes:   apiTypes,
						Severity:   sev,
						Repository: d.searchRepository("", apiTypes),
						Limit:      limit,
					})
					if err != nil {
						parts = append(parts, fmt.Sprintf("--- %s (%s) ---\nError: %v", name, sev, err))
						continue
					}
					if len(result.Findings) == 0 {
						continue
					}
					b, _ := json.MarshalIndent(result.Findings, "", "  ")
					parts = append(parts, fmt.Sprintf("--- %s (%s) ---\n%s", name, sev, string(b)))
				}
			}
			note := d.fanOutNote()
			if len(parts) == 0 {
				return withNote(toolResult("No critical or high severity findings found."), note), nil
			}
			return withNote(toolResult(strings.Join(parts, "\n\n")), note), nil
		},
	)

	s.AddTool(
		readOnlyTool("get_security_trends",
			mcp.WithDescription("Security metrics: current posture overview plus how it has changed over time."),
			mcp.WithString("period", mcp.Description("Time period"), mcp.Enum("7d", "30d", "90d", "365d")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			period := getStringArg(req.GetArguments(), "period")
			if period == "" {
				period = "30d"
			}
			overview, err := c.CreateAdminMetricsOverview(ctx, metricsOverviewInput(d.metricsRepository()))
			if err != nil {
				return toolError(err), nil
			}
			overTime, err := c.CreateAdminMetricsOverTime(ctx, metricsOverTimeInput(period, d.metricsRepository()))
			if err != nil {
				return toolError(err), nil
			}
			ovBytes, _ := json.Marshal(overview)
			otBytes, _ := json.Marshal(overTime)
			return withNote(toolResult(fmt.Sprintf("--- Current Overview ---\n%s\n\n--- Trends (%s) ---\n%s", string(ovBytes), period, string(otBytes))), d.metricsRepositoryNote()), nil
		},
	)
}
