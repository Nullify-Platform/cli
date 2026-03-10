package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/nullify-platform/cli/internal/client"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerCompositeTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	s.AddTool(
		mcp.NewTool(
			"get_security_posture_summary",
			mcp.WithDescription("Get a high-level security posture summary across all finding types (SAST, SCA dependencies, SCA containers, secrets, pentest, bughunt, CSPM). Returns counts by severity for each finding type. This is typically the first tool an AI agent should call to understand the overall security state."),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			type findingCount struct {
				Type  string          `json:"type"`
				Error string          `json:"error,omitempty"`
				Data  json.RawMessage `json:"data,omitempty"`
			}

			endpoints := []struct {
				name string
				path string
			}{
				{"sast", "/sast/findings"},
				{"sca_dependencies", "/sca/dependencies/findings"},
				{"sca_containers", "/sca/containers/findings"},
				{"secrets", "/secrets/findings"},
				{"pentest", "/dast/pentest/findings"},
				{"bughunt", "/dast/bughunt/findings"},
				{"cspm", "/cspm/findings"},
			}

			var results []findingCount
			epQS := buildQueryString(queryParams, "limit", "1")
			for _, ep := range endpoints {
				result, err := doGet(ctx, c, ep.path+epQS)
				if err != nil {
					results = append(results, findingCount{Type: ep.name, Error: err.Error()})
					continue
				}
				// Extract the text content from the result
				if len(result.Content) > 0 {
					if tc, ok := result.Content[0].(mcp.TextContent); ok {
						results = append(results, findingCount{Type: ep.name, Data: json.RawMessage(tc.Text)})
					}
				}
			}

			summaryJSON, _ := json.MarshalIndent(results, "", "  ")
			return toolResult(string(summaryJSON)), nil
		},
	)

	s.AddTool(
		mcp.NewTool(
			"get_findings_for_repo",
			mcp.WithDescription("Get all security findings for a specific repository across all finding types (SAST, SCA dependencies, SCA containers, secrets, pentest, bughunt, CSPM). Returns a merged list of findings from all scanners. This is the most common tool for investigating a specific repository's security posture."),
			mcp.WithString("repository", mcp.Required(), mcp.Description("Repository name to get findings for")),
			mcp.WithString("severity", mcp.Description("Filter by severity"), mcp.Enum("critical", "high", "medium", "low")),
			mcp.WithNumber("limit", mcp.Description("Max results per finding type (default 20)")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			repo := getStringArg(args, "repository")
			severity := getStringArg(args, "severity")
			limit := getIntArg(args, "limit", 20)

			extra := []string{"repository", repo}
			if severity != "" {
				extra = append(extra, "severity", severity)
			}
			extra = append(extra, "limit", fmt.Sprintf("%d", limit))

			endpoints := []struct {
				name string
				path string
			}{
				{"sast", "/sast/findings"},
				{"sca_dependencies", "/sca/dependencies/findings"},
				{"sca_containers", "/sca/containers/findings"},
				{"secrets", "/secrets/findings"},
				{"pentest", "/dast/pentest/findings"},
				{"bughunt", "/dast/bughunt/findings"},
				{"cspm", "/cspm/findings"},
			}

			var parts []string
			qs := buildQueryString(queryParams, extra...)
			for _, ep := range endpoints {
				result, err := doGet(ctx, c, ep.path+qs)
				if err != nil {
					parts = append(parts, fmt.Sprintf("--- %s ---\nError: %v", ep.name, err))
					continue
				}
				if len(result.Content) > 0 {
					if tc, ok := result.Content[0].(mcp.TextContent); ok {
						parts = append(parts, fmt.Sprintf("--- %s ---\n%s", ep.name, tc.Text))
					}
				}
			}

			return toolResult(strings.Join(parts, "\n\n")), nil
		},
	)

	s.AddTool(
		mcp.NewTool(
			"remediate_finding",
			mcp.WithDescription("Orchestrate full remediation of a finding: generate autofix, get diff, and create PR."),
			mcp.WithString("finding_type", mcp.Required(), mcp.Description("Type of finding"), mcp.Enum("sast", "sca")),
			mcp.WithString("finding_id", mcp.Required(), mcp.Description("The finding ID")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			findingType := getStringArg(args, "finding_type")
			findingID := getStringArg(args, "finding_id")
			qs := buildQueryString(queryParams)

			var basePath string
			switch findingType {
			case "sast":
				basePath = "/sast/findings"
			case "sca":
				basePath = "/sca/dependencies/findings"
			default:
				return toolError(fmt.Errorf("unsupported finding type: %s", findingType)), nil
			}

			// Step 1: Generate autofix
			fixResult, err := doPost(ctx, c, fmt.Sprintf("%s/%s/autofix/fix%s", basePath, url.PathEscape(findingID), qs), nil)
			if err != nil {
				return toolError(fmt.Errorf("generate autofix failed: %w", err)), nil
			}
			if fixResult.IsError {
				return fixResult, nil
			}

			// Step 2: Get diff
			diffResult, err := doGet(ctx, c, fmt.Sprintf("%s/%s/autofix/cache/diff%s", basePath, url.PathEscape(findingID), qs))
			if err != nil {
				return toolError(fmt.Errorf("get diff failed: %w", err)), nil
			}

			// Step 3: Create PR
			prResult, err := doPost(ctx, c, fmt.Sprintf("%s/%s/autofix/cache/create_pr%s", basePath, url.PathEscape(findingID), qs), nil)
			if err != nil {
				return toolError(fmt.Errorf("create PR failed: %w", err)), nil
			}

			var resultParts []string
			resultParts = append(resultParts, "--- autofix diff ---")
			if len(diffResult.Content) > 0 {
				if tc, ok := diffResult.Content[0].(mcp.TextContent); ok {
					resultParts = append(resultParts, tc.Text)
				}
			}
			resultParts = append(resultParts, "\n--- PR created ---")
			if len(prResult.Content) > 0 {
				if tc, ok := prResult.Content[0].(mcp.TextContent); ok {
					resultParts = append(resultParts, tc.Text)
				}
			}

			return toolResult(strings.Join(resultParts, "\n")), nil
		},
	)

	s.AddTool(
		mcp.NewTool(
			"get_critical_path",
			mcp.WithDescription("Get all critical and high severity findings across all types, sorted by severity. Useful for identifying the most urgent security issues."),
			mcp.WithNumber("limit", mcp.Description("Max results per finding type (default 10)")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			limit := getIntArg(args, "limit", 10)

			endpoints := []struct {
				name string
				path string
			}{
				{"sast", "/sast/findings"},
				{"sca_dependencies", "/sca/dependencies/findings"},
				{"sca_containers", "/sca/containers/findings"},
				{"secrets", "/secrets/findings"},
				{"pentest", "/dast/pentest/findings"},
				{"bughunt", "/dast/bughunt/findings"},
				{"cspm", "/cspm/findings"},
			}

			var parts []string
			for _, ep := range endpoints {
				for _, sev := range []string{"critical", "high"} {
					extra := []string{"severity", sev, "limit", fmt.Sprintf("%d", limit)}
					qs := buildQueryString(queryParams, extra...)
					result, err := doGet(ctx, c, ep.path+qs)
					if err != nil {
						continue
					}
					if len(result.Content) > 0 {
						if tc, ok := result.Content[0].(mcp.TextContent); ok {
							parts = append(parts, fmt.Sprintf("--- %s (%s) ---\n%s", ep.name, sev, tc.Text))
						}
					}
				}
			}

			if len(parts) == 0 {
				return toolResult("No critical or high severity findings found."), nil
			}

			return toolResult(strings.Join(parts, "\n\n")), nil
		},
	)

	s.AddTool(
		mcp.NewTool(
			"get_security_trends",
			mcp.WithDescription("Get security metrics trends showing how the security posture has changed over time."),
			mcp.WithString("period", mcp.Description("Time period"), mcp.Enum("7d", "30d", "90d", "365d")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			period := getStringArg(args, "period")
			if period == "" {
				period = "30d"
			}

			// Get overview
			overviewQS := buildQueryString(queryParams)
			overviewResult, err := doGet(ctx, c, "/admin/metrics/overview"+overviewQS)
			if err != nil {
				return toolError(err), nil
			}

			// Get over-time data
			timeQS := buildQueryString(queryParams, "period", period)
			timeResult, err := doGet(ctx, c, "/admin/metrics/over-time"+timeQS)
			if err != nil {
				return toolError(err), nil
			}

			var parts []string
			parts = append(parts, "--- Current Overview ---")
			if len(overviewResult.Content) > 0 {
				if tc, ok := overviewResult.Content[0].(mcp.TextContent); ok {
					parts = append(parts, tc.Text)
				}
			}
			parts = append(parts, fmt.Sprintf("\n--- Trends (%s) ---", period))
			if len(timeResult.Content) > 0 {
				if tc, ok := timeResult.Content[0].(mcp.TextContent); ok {
					parts = append(parts, tc.Text)
				}
			}

			return toolResult(strings.Join(parts, "\n")), nil
		},
	)
}
