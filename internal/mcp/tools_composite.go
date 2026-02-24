package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nullify-platform/cli/internal/client"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerCompositeTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	s.AddTool(
		mcp.NewTool(
			"get_security_posture_summary",
			mcp.WithDescription("Get a high-level security posture summary across all finding types (SAST, SCA dependencies, SCA containers, secrets, DAST). Returns counts by severity for each finding type. This is typically the first tool an AI agent should call to understand the overall security state."),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			qs := buildQueryString(queryParams)

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
				{"dast_pentest", "/dast/pentest/findings"},
			}

			var results []findingCount
			for _, ep := range endpoints {
				result, err := doGet(c, ep.path+qs+"&limit=1")
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
			mcp.WithDescription("Get all security findings for a specific repository across all finding types (SAST, SCA, secrets). Returns a merged list of findings from all scanners. This is the most common tool for investigating a specific repository's security posture."),
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
			}

			var parts []string
			for _, ep := range endpoints {
				qs := buildQueryString(queryParams, extra...)
				result, err := doGet(c, ep.path+qs)
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
}
