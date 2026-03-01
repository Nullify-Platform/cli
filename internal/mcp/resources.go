package mcp

import (
	"context"

	"github.com/nullify-platform/cli/internal/client"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerResources(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	s.AddResource(
		mcplib.Resource{
			URI:         "nullify://posture",
			Name:        "Security Posture",
			Description: "Current security posture summary across all finding types",
			MIMEType:    "application/json",
		},
		func(ctx context.Context, request mcplib.ReadResourceRequest) ([]mcplib.ResourceContents, error) {
			qs := buildQueryString(queryParams)
			result, err := doGet(ctx, c, "/admin/metrics/overview"+qs)
			if err != nil {
				return nil, err
			}

			var text string
			if len(result.Content) > 0 {
				if tc, ok := result.Content[0].(mcplib.TextContent); ok {
					text = tc.Text
				}
			}

			return []mcplib.ResourceContents{
				mcplib.TextResourceContents{
					URI:      "nullify://posture",
					MIMEType: "application/json",
					Text:     text,
				},
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
			qs := buildQueryString(queryParams)
			result, err := doGet(ctx, c, "/classifier/repositories"+qs)
			if err != nil {
				return nil, err
			}

			var text string
			if len(result.Content) > 0 {
				if tc, ok := result.Content[0].(mcplib.TextContent); ok {
					text = tc.Text
				}
			}

			return []mcplib.ResourceContents{
				mcplib.TextResourceContents{
					URI:      "nullify://repos",
					MIMEType: "application/json",
					Text:     text,
				},
			}, nil
		},
	)
}
