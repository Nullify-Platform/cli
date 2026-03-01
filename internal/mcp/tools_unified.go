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

type findingTypeConfig struct {
	basePath string
	triage   bool
	autofix  bool
	ticket   bool
	events   bool
}

var findingTypes = map[string]findingTypeConfig{
	"sast":           {basePath: "/sast/findings", triage: true, autofix: true, ticket: true, events: true},
	"sca_dependency": {basePath: "/sca/dependencies/findings", triage: true, autofix: true, ticket: true, events: true},
	"sca_container":  {basePath: "/sca/containers/findings", triage: true},
	"secrets":        {basePath: "/secrets/findings", triage: true, ticket: true, events: true},
	"pentest":        {basePath: "/dast/pentest/findings", triage: true, ticket: true, events: true},
	"bughunt":        {basePath: "/dast/bughunt/findings"},
	"cspm":           {basePath: "/cspm/findings"},
}

func allFindingTypeNames() []string {
	names := make([]string, 0, len(findingTypes))
	for name := range findingTypes {
		names = append(names, name)
	}
	return names
}

func filterTypesByCapability(capFn func(findingTypeConfig) bool) []string {
	var names []string
	for name, cfg := range findingTypes {
		if capFn(cfg) {
			names = append(names, name)
		}
	}
	return names
}

func resolveFindingType(typeName string) (findingTypeConfig, error) {
	cfg, ok := findingTypes[typeName]
	if !ok {
		return findingTypeConfig{}, fmt.Errorf("unknown finding type %q. Valid types: %s", typeName, strings.Join(allFindingTypeNames(), ", "))
	}
	return cfg, nil
}

func registerUnifiedTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	allTypes := allFindingTypeNames()
	triageTypes := filterTypesByCapability(func(c findingTypeConfig) bool { return c.triage })
	autofixTypes := filterTypesByCapability(func(c findingTypeConfig) bool { return c.autofix })
	ticketTypes := filterTypesByCapability(func(c findingTypeConfig) bool { return c.ticket })
	eventTypes := filterTypesByCapability(func(c findingTypeConfig) bool { return c.events })

	// 1. nullify_search_findings
	s.AddTool(
		mcp.NewTool(
			"nullify_search_findings",
			mcp.WithDescription("Search security findings across all or a specific scanner type. When type is omitted, queries all scanner types and merges results."),
			mcp.WithString("type", mcp.Description("Finding type to search"), mcp.Enum(allTypes...)),
			mcp.WithString("severity", mcp.Description("Filter by severity"), mcp.Enum("critical", "high", "medium", "low")),
			mcp.WithString("status", mcp.Description("Filter by status"), mcp.Enum("open", "fixed", "false_positive", "accepted_risk")),
			mcp.WithString("repository", mcp.Description("Filter by repository name")),
			mcp.WithNumber("limit", mcp.Description("Max results per finding type (default 20)")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			typeName := getStringArg(args, "type")
			severity := getStringArg(args, "severity")
			status := getStringArg(args, "status")
			repository := getStringArg(args, "repository")
			limit := getIntArg(args, "limit", 20)

			extra := []string{}
			if severity != "" {
				extra = append(extra, "severity", severity)
			}
			if status != "" {
				extra = append(extra, "status", status)
			}
			if repository != "" {
				extra = append(extra, "repository", repository)
			}
			extra = append(extra, "limit", fmt.Sprintf("%d", limit))
			qs := buildQueryString(queryParams, extra...)

			type searchResult struct {
				Type  string          `json:"type"`
				Error string          `json:"error,omitempty"`
				Data  json.RawMessage `json:"data,omitempty"`
			}

			// Determine which types to query
			types := allTypes
			if typeName != "" {
				if _, err := resolveFindingType(typeName); err != nil {
					return toolError(err), nil
				}
				types = []string{typeName}
			}

			var results []searchResult
			for _, t := range types {
				cfg := findingTypes[t]
				result, err := doGet(ctx, c, cfg.basePath+qs)
				if err != nil {
					results = append(results, searchResult{Type: t, Error: err.Error()})
					continue
				}
				if len(result.Content) > 0 {
					if tc, ok := result.Content[0].(mcp.TextContent); ok {
						results = append(results, searchResult{Type: t, Data: json.RawMessage(tc.Text)})
					}
				}
			}

			out, _ := json.MarshalIndent(results, "", "  ")
			return toolResult(string(out)), nil
		},
	)

	// 2. nullify_get_finding
	s.AddTool(
		mcp.NewTool(
			"nullify_get_finding",
			mcp.WithDescription("Get details of a specific finding by type and ID."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Finding type"), mcp.Enum(allTypes...)),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			typeName := getStringArg(args, "type")
			id := getStringArg(args, "id")

			cfg, err := resolveFindingType(typeName)
			if err != nil {
				return toolError(err), nil
			}

			qs := buildQueryString(queryParams)
			return doGet(ctx, c, fmt.Sprintf("%s/%s%s", cfg.basePath, id, qs))
		},
	)

	// 3. nullify_triage_finding
	s.AddTool(
		mcp.NewTool(
			"nullify_triage_finding",
			mcp.WithDescription("Update the triage status of a finding."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Finding type"), mcp.Enum(triageTypes...)),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
			mcp.WithString("status", mcp.Required(), mcp.Description("New status"), mcp.Enum("open", "false_positive", "accepted_risk")),
			mcp.WithString("reason", mcp.Description("Reason for the status change")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			typeName := getStringArg(args, "type")
			id := getStringArg(args, "id")
			newStatus := getStringArg(args, "status")
			reason := getStringArg(args, "reason")

			cfg, err := resolveFindingType(typeName)
			if err != nil {
				return toolError(err), nil
			}

			payload := map[string]string{"status": newStatus}
			if reason != "" {
				payload["reason"] = reason
			}

			qs := buildQueryString(queryParams)
			return doPut(ctx, c, fmt.Sprintf("%s/%s%s", cfg.basePath, id, qs), payload)
		},
	)

	// 4. nullify_create_ticket
	s.AddTool(
		mcp.NewTool(
			"nullify_create_ticket",
			mcp.WithDescription("Create a ticket (e.g., Jira, GitHub issue) for a finding."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Finding type"), mcp.Enum(ticketTypes...)),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			typeName := getStringArg(args, "type")
			id := getStringArg(args, "id")

			cfg, err := resolveFindingType(typeName)
			if err != nil {
				return toolError(err), nil
			}

			qs := buildQueryString(queryParams)
			return doPost(ctx, c, fmt.Sprintf("%s/%s/ticket%s", cfg.basePath, id, qs), nil)
		},
	)

	// 5. nullify_get_finding_events
	s.AddTool(
		mcp.NewTool(
			"nullify_get_finding_events",
			mcp.WithDescription("Get the event history for a finding."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Finding type"), mcp.Enum(eventTypes...)),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			typeName := getStringArg(args, "type")
			id := getStringArg(args, "id")

			cfg, err := resolveFindingType(typeName)
			if err != nil {
				return toolError(err), nil
			}

			qs := buildQueryString(queryParams)
			return doGet(ctx, c, fmt.Sprintf("%s/%s/events%s", cfg.basePath, id, qs))
		},
	)

	// 6. nullify_fix_finding
	s.AddTool(
		mcp.NewTool(
			"nullify_fix_finding",
			mcp.WithDescription("Generate an autofix for a finding and optionally create a PR. Orchestrates: generate fix → get diff → create PR."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Finding type"), mcp.Enum(autofixTypes...)),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
			mcp.WithBoolean("create_pr", mcp.Description("Create a PR with the fix (default true)")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			typeName := getStringArg(args, "type")
			id := getStringArg(args, "id")

			createPR := true
			if v, ok := args["create_pr"]; ok {
				if b, ok := v.(bool); ok {
					createPR = b
				}
			}

			cfg, err := resolveFindingType(typeName)
			if err != nil {
				return toolError(err), nil
			}

			qs := buildQueryString(queryParams)

			// Step 1: Generate autofix
			fixResult, err := doPost(ctx, c, fmt.Sprintf("%s/%s/autofix/fix%s", cfg.basePath, id, qs), nil)
			if err != nil {
				return toolError(fmt.Errorf("generate autofix failed: %w", err)), nil
			}
			if fixResult.IsError {
				return fixResult, nil
			}

			// Step 2: Get diff
			diffResult, err := doGet(ctx, c, fmt.Sprintf("%s/%s/autofix/cache/diff%s", cfg.basePath, id, qs))
			if err != nil {
				return toolError(fmt.Errorf("get diff failed: %w", err)), nil
			}

			var resultParts []string
			resultParts = append(resultParts, "--- autofix diff ---")
			if len(diffResult.Content) > 0 {
				if tc, ok := diffResult.Content[0].(mcp.TextContent); ok {
					resultParts = append(resultParts, tc.Text)
				}
			}

			// Step 3: Optionally create PR
			if createPR {
				prResult, err := doPost(ctx, c, fmt.Sprintf("%s/%s/autofix/cache/create_pr%s", cfg.basePath, id, qs), nil)
				if err != nil {
					return toolError(fmt.Errorf("create PR failed: %w", err)), nil
				}
				resultParts = append(resultParts, "\n--- PR created ---")
				if len(prResult.Content) > 0 {
					if tc, ok := prResult.Content[0].(mcp.TextContent); ok {
						resultParts = append(resultParts, tc.Text)
					}
				}
			}

			return toolResult(strings.Join(resultParts, "\n")), nil
		},
	)
}
