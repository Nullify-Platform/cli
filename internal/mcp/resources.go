package mcp

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/nullify-platform/cli/internal/api"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerResources(s *server.MCPServer, c *api.Client) {
	s.AddResource(
		mcplib.Resource{
			URI:         "nullify://posture",
			Name:        "Security Posture",
			Description: "Current security posture summary across all finding types",
			MIMEType:    "application/json",
		},
		func(ctx context.Context, request mcplib.ReadResourceRequest) ([]mcplib.ResourceContents, error) {
			data, err := c.CreateAdminMetricsOverview(ctx, nil, jsonReader(metricsOverviewBody()))
			if err != nil {
				return nil, err
			}
			return []mcplib.ResourceContents{
				mcplib.TextResourceContents{URI: "nullify://posture", MIMEType: "application/json", Text: string(data)},
			}, nil
		},
	)

	s.AddResource(
		mcplib.Resource{
			URI:         "nullify://repos",
			Name:        "Monitored Repositories",
			Description: "List of repositories monitored by Nullify",
			MIMEType:    "application/json",
		},
		func(ctx context.Context, request mcplib.ReadResourceRequest) ([]mcplib.ResourceContents, error) {
			data, err := c.ListContextRepositories(ctx, nil)
			if err != nil {
				return nil, err
			}
			return []mcplib.ResourceContents{
				mcplib.TextResourceContents{URI: "nullify://repos", MIMEType: "application/json", Text: string(data)},
			}, nil
		},
	)

	s.AddResource(
		mcplib.Resource{
			URI:         "nullify://recent-findings",
			Name:        "Recent Findings",
			Description: "Recent findings across the top scanner types (SAST, SCA dependencies, secrets)",
			MIMEType:    "application/json",
		},
		func(ctx context.Context, request mcplib.ReadResourceRequest) ([]mcplib.ResourceContents, error) {
			type entry struct {
				Type  string          `json:"type"`
				Error string          `json:"error,omitempty"`
				Data  json.RawMessage `json:"data,omitempty"`
			}
			recent := []struct {
				name string
				list methodNoBody
			}{
				{"sast", (*api.Client).ListSastFindings},
				{"sca_dependencies", (*api.Client).ListScaDependenciesFindings},
				{"secrets", (*api.Client).ListSecretsFindings},
			}
			var out []entry
			for _, r := range recent {
				p := url.Values{}
				p.Set("limit", "5")
				data, err := r.list(c, ctx, p)
				if err != nil {
					out = append(out, entry{Type: r.name, Error: err.Error()})
					continue
				}
				out = append(out, entry{Type: r.name, Data: json.RawMessage(data)})
			}
			b, _ := json.MarshalIndent(out, "", "  ")
			return []mcplib.ResourceContents{
				mcplib.TextResourceContents{URI: "nullify://recent-findings", MIMEType: "application/json", Text: string(b)},
			}, nil
		},
	)
}
