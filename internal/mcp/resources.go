package mcp

import (
	"context"
	"encoding/json"

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
			out, err := c.CreateAdminMetricsOverview(ctx, metricsOverviewInput())
			if err != nil {
				return nil, err
			}
			data, err := json.Marshal(out)
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
			out, err := c.ListContextRepositories(ctx, api.ListContextRepositoriesInput{})
			if err != nil {
				return nil, err
			}
			data, err := json.Marshal(out)
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
				list func(ctx context.Context, c *api.Client) (json.RawMessage, error)
			}{
				{"sast", func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
					return marshalOut(c.ListSastFindings(ctx, api.ListSastFindingsInput{Limit: limitPtr(5)}))
				}},
				{"sca_dependencies", func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
					return marshalOut(c.ListScaDependenciesFindings(ctx, api.ListScaDependenciesFindingsInput{Limit: limitPtr(5)}))
				}},
				{"secrets", func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
					return marshalOut(c.ListSecretsFindings(ctx, api.ListSecretsFindingsInput{Limit: limitPtr(5)}))
				}},
			}
			var out []entry
			for _, r := range recent {
				data, err := r.list(ctx, c)
				if err != nil {
					out = append(out, entry{Type: r.name, Error: err.Error()})
					continue
				}
				out = append(out, entry{Type: r.name, Data: data})
			}
			b, _ := json.MarshalIndent(out, "", "  ")
			return []mcplib.ResourceContents{
				mcplib.TextResourceContents{URI: "nullify://recent-findings", MIMEType: "application/json", Text: string(b)},
			}, nil
		},
	)
}
