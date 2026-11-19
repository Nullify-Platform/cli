package mcp

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/nullify-platform/cli/internal/api"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerResources(s *server.MCPServer, c *api.Client, d Defaults) {
	s.AddResource(
		mcplib.Resource{
			URI:         "nullify://posture",
			Name:        "Security Posture",
			Description: "Current security posture summary across all finding types",
			MIMEType:    "application/json",
		},
		func(ctx context.Context, request mcplib.ReadResourceRequest) ([]mcplib.ResourceContents, error) {
			out, err := c.CreateAdminMetricsOverview(ctx, metricsOverviewInput(d.metricsRepository()))
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
			Description: "The " + strconv.Itoa(recentFindingsCount) + " newest findings of SAST, SCA dependencies and secret credentials, newest first, across every repository",
			MIMEType:    "application/json",
		},
		func(ctx context.Context, request mcplib.ReadResourceRequest) ([]mcplib.ResourceContents, error) {
			type entry struct {
				Type  string          `json:"type"`
				Error string          `json:"error,omitempty"`
				Data  json.RawMessage `json:"data,omitempty"`
			}
			var out []entry
			for _, r := range recentListers {
				data, err := r.list(ctx, c)
				if err != nil {
					out = append(out, entry{Type: r.name, Error: err.Error()})
					continue
				}
				out = append(out, entry{Type: r.name, Data: data})
			}
			b, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				return nil, err
			}
			return []mcplib.ResourceContents{
				mcplib.TextResourceContents{URI: "nullify://recent-findings", MIMEType: "application/json", Text: string(b)},
			}, nil
		},
	)
}

// recentFindingsCount is how many findings of each type the recent-findings
// resource returns.
const recentFindingsCount = 5

// recentListers list the newest findings of each type in the recent-findings
// resource. The scanner list routes order by priority unless sortBy is time.
var recentListers = []struct {
	name string
	list func(ctx context.Context, c *api.Client) (json.RawMessage, error)
}{
	{"sast", func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
		return marshalOut(c.ListSastFindings(ctx, api.ListSastFindingsInput{
			Limit: limitPtr(recentFindingsCount), SortBy: optionalString("time"), Sort: optionalString("desc"),
		}))
	}},
	{"sca_dependencies", func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
		return marshalOut(c.ListScaDependenciesFindings(ctx, api.ListScaDependenciesFindingsInput{
			Limit: limitPtr(recentFindingsCount), SortBy: optionalString("time"), Sort: optionalString("desc"),
		}))
	}},
	{"secrets", func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
		return marshalOut(c.ListSecretsCredentialsFindings(ctx, api.ListSecretsCredentialsFindingsInput{
			Limit: limitPtr(recentFindingsCount), SortBy: optionalString("time"), Sort: optionalString("desc"),
		}))
	}},
}
