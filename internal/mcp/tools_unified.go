package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
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
	"sast":             {basePath: "/sast/findings", triage: true, autofix: true, ticket: true, events: true},
	"sca_dependencies": {basePath: "/sca/dependencies/findings", triage: true, autofix: true, ticket: true, events: true},
	"sca_containers":   {basePath: "/sca/containers/findings", triage: true},
	"secrets":          {basePath: "/secrets/findings", triage: true, ticket: true, events: true},
	"pentest":          {basePath: "/dast/pentest/findings", triage: true, ticket: true, events: true},
	"bughunt":          {basePath: "/dast/bughunt/findings"},
	"cspm":             {basePath: "/cspm/findings"},
}

func allFindingTypeNames() []string {
	names := make([]string, 0, len(findingTypes))
	for name := range findingTypes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func filterTypesByCapability(capFn func(findingTypeConfig) bool) []string {
	var names []string
	for name, cfg := range findingTypes {
		if capFn(cfg) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
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
			mcp.WithDescription("Search security findings across all or a specific scanner type. Automatically paginates to return up to limit total findings."),
			mcp.WithString("type", mcp.Description("Finding type to search"), mcp.Enum(allTypes...)),
			mcp.WithString("severity", mcp.Description("Filter by severity"), mcp.Enum("critical", "high", "medium", "low")),
			mcp.WithString("status", mcp.Description("Filter by status"), mcp.Enum("open", "fixed", "false_positive", "accepted_risk")),
			mcp.WithString("repository", mcp.Description("Filter by repository name")),
			mcp.WithNumber("limit", mcp.Description("Max total findings to return across all pages (default 100)")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			typeName := getStringArg(args, "type")
			severity := getStringArg(args, "severity")
			status := getStringArg(args, "status")
			repository := getStringArg(args, "repository")
			limit := getIntArg(args, "limit", 100)

			qs := buildQueryString(queryParams)

			type unifiedResponse struct {
				Findings    []json.RawMessage `json:"findings"`
				Total       int               `json:"total"`
				HasMoreData bool              `json:"hasMoreData"`
				ScrollID    *string           `json:"scrollId"`
			}

			type searchOutput struct {
				Findings []json.RawMessage `json:"findings"`
				Total    int               `json:"total"`
			}

			allFindings := make([]json.RawMessage, 0)
			var scrollID string
			var lastTotal int

			for {
				pageSize := 100
				remaining := limit - len(allFindings)
				if remaining <= 0 {
					break
				}
				if remaining < pageSize {
					pageSize = remaining
				}

				query := map[string]any{
					"pageSize": pageSize,
				}
				if repository != "" {
					query["repository"] = []string{repository}
				}
				if severity != "" {
					query["severity"] = []string{severity}
				}
				if typeName != "" {
					if _, err := resolveFindingType(typeName); err != nil {
						return toolError(err), nil
					}
					query["type"] = []string{typeName}
				}
				if scrollID != "" {
					query["scrollId"] = scrollID
				}
				if status != "" {
					switch status {
					case "open":
						query["isResolved"] = false
					case "fixed":
						query["isFixed"] = true
					case "false_positive":
						query["isFalsePositive"] = true
					case "accepted_risk":
						query["isAllowlisted"] = true
					}
				}

				result, err := doPost(ctx, c, "/admin/findings"+qs, map[string]any{"query": query})
				if err != nil {
					return toolError(err), nil
				}
				if result.IsError {
					return result, nil
				}
				if len(result.Content) == 0 {
					break
				}
				tc, ok := result.Content[0].(mcp.TextContent)
				if !ok {
					break
				}

				var resp unifiedResponse
				if err := json.Unmarshal([]byte(tc.Text), &resp); err != nil {
					return toolError(err), nil
				}

				allFindings = append(allFindings, resp.Findings...)
				lastTotal = resp.Total

				if !resp.HasMoreData || resp.ScrollID == nil || *resp.ScrollID == "" {
					break
				}
				scrollID = *resp.ScrollID
			}

			out, _ := json.MarshalIndent(searchOutput{Findings: allFindings, Total: lastTotal}, "", "  ")
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
			return doGet(ctx, c, fmt.Sprintf("%s/%s%s", cfg.basePath, url.PathEscape(id), qs))
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
			return doPut(ctx, c, fmt.Sprintf("%s/%s%s", cfg.basePath, url.PathEscape(id), qs), payload)
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
			return doPost(ctx, c, fmt.Sprintf("%s/%s/ticket%s", cfg.basePath, url.PathEscape(id), qs), nil)
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
			return doGet(ctx, c, fmt.Sprintf("%s/%s/events%s", cfg.basePath, url.PathEscape(id), qs))
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
			fixResult, err := doPost(ctx, c, fmt.Sprintf("%s/%s/autofix/fix%s", cfg.basePath, url.PathEscape(id), qs), nil)
			if err != nil {
				return toolError(fmt.Errorf("generate autofix failed: %w", err)), nil
			}
			if fixResult.IsError {
				return fixResult, nil
			}

			// Step 2: Get diff
			diffResult, err := doGet(ctx, c, fmt.Sprintf("%s/%s/autofix/cache/diff%s", cfg.basePath, url.PathEscape(id), qs))
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
				prResult, err := doPost(ctx, c, fmt.Sprintf("%s/%s/autofix/cache/create_pr%s", cfg.basePath, url.PathEscape(id), qs), nil)
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
