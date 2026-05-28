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

// registerThreatTools exposes the manager threat-investigations catalog:
// browsing analyzed CVEs/advisories and recording a new investigation.
func registerThreatTools(s *server.MCPServer, c *api.Client) {
	s.AddTool(
		mcp.NewTool("nullify_list_threat_investigations",
			mcp.WithDescription("List threat investigations (the org's threat-intelligence catalog). Paginates automatically up to limit."),
			mcp.WithNumber("limit", mcp.Description("Max total investigations across pages (default 100)")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			limit := getIntArg(req.GetArguments(), "limit", 100)
			all, err := listThreatInvestigations(ctx, c, limit)
			if err != nil {
				return toolError(err), nil
			}
			out, _ := json.MarshalIndent(map[string]any{"threatInvestigations": all, "numItems": len(all)}, "", "  ")
			return toolResult(string(out)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("nullify_get_threat_investigation",
			mcp.WithDescription("Get a single threat investigation by ID."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The threat investigation ID")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return wrapTyped(c.GetManagerThreatInvestigationsThreatInvestigationId(ctx, api.GetManagerThreatInvestigationsThreatInvestigationIdInput{
				ThreatInvestigationID: getStringArg(req.GetArguments(), "id"),
			}))
		},
	)

	s.AddTool(
		mcp.NewTool("nullify_create_threat_investigation",
			mcp.WithDescription("Create a threat investigation entry in the threat-intelligence catalog."),
			mcp.WithString("title", mcp.Required(), mcp.Description("Short title of the threat")),
			mcp.WithString("description", mcp.Description("Detailed description")),
			mcp.WithString("severity", mcp.Description("Severity"), mcp.Enum("critical", "high", "medium", "low")),
			mcp.WithString("advice", mcp.Description("Remediation advice")),
			mcp.WithString("ecosystem", mcp.Description("Affected ecosystem (e.g. npm, pypi, go)")),
			mcp.WithString("keywords", mcp.Description("Comma-separated keywords")),
			mcp.WithNumber("cvss", mcp.Description("CVSS score")),
			mcp.WithString("cve_ids", mcp.Description("Comma-separated CVE IDs")),
			mcp.WithString("article_links", mcp.Description("Comma-separated reference URLs")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			in := api.CreateManagerThreatInvestigationsInput{
				Title: getStringArg(args, "title"),
			}
			if v := getStringArg(args, "description"); v != "" {
				in.Description = &v
			}
			if v := getStringArg(args, "severity"); v != "" {
				in.Severity = &v
			}
			if v := getStringArg(args, "advice"); v != "" {
				in.Advice = &v
			}
			if v := getStringArg(args, "ecosystem"); v != "" {
				in.Ecosystem = &v
			}
			if v := getStringArg(args, "keywords"); v != "" {
				in.Keywords = &v
			}
			if v, ok := args["cvss"]; ok {
				switch v.(type) {
				case float64, int:
					n := getFloatArg(args, "cvss")
					in.Cvss = &n
				default:
					return toolError(fmt.Errorf("cvss must be a number, got %T", v)), nil
				}
			}
			if v := splitCSV(getStringArg(args, "cve_ids")); len(v) > 0 {
				in.CveIds = v
			}
			if v := splitCSV(getStringArg(args, "article_links")); len(v) > 0 {
				in.ArticleLinks = v
			}
			return wrapTyped(c.CreateManagerThreatInvestigations(ctx, in))
		},
	)
}

// listThreatInvestigations paginates GET /manager/threat-investigations up to
// limit. The server's `numItems` is the per-page count, not the total (see
// manager/internal/endpoints/threatinvestigations_get.go), so we can't use it
// as a stop signal — only a short page or an empty page tells us we're done.
func listThreatInvestigations(ctx context.Context, c *api.Client, limit int) ([]json.RawMessage, error) {
	const pageSize = 50
	all := make([]json.RawMessage, 0)
	for page := 1; len(all) < limit; page++ {
		p, ps := page, pageSize
		resp, err := c.ListManagerThreatInvestigations(ctx, api.ListManagerThreatInvestigationsInput{
			Page:     &p,
			PageSize: &ps,
		})
		if err != nil {
			return nil, err
		}
		if len(resp.ThreatInvestigations) == 0 {
			break
		}
		for _, ti := range resp.ThreatInvestigations {
			b, err := json.Marshal(ti)
			if err != nil {
				return nil, err
			}
			all = append(all, b)
		}
		if len(resp.ThreatInvestigations) < pageSize {
			break
		}
	}
	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
