package mcp

import (
	"context"
	"encoding/json"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/findings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerUnifiedTools(s *server.MCPServer, c *api.Client) {
	registerSearchTool(s, c)
	registerFindingEventsTool(s, c)
	for _, verb := range findings.Verbs {
		if !verb.OptIn {
			registerVerbTool(s, c, verb)
		}
	}
	registerFeedbackTools(s, c)
	registerFixTool(s, c)
}

func registerOptInFindingTools(s *server.MCPServer, c *api.Client) {
	for _, verb := range findings.Verbs {
		if verb.OptIn {
			registerVerbTool(s, c, verb)
		}
	}
}

func registerSearchTool(s *server.MCPServer, c *api.Client) {
	s.AddTool(
		readOnlyTool(
			"nullify_search_findings",
			mcp.WithDescription("Search security findings across all or a specific scanner type. Paginates automatically up to limit. The result reports total, returned and truncated, so that an empty result can be told apart from a cut-off one. An access failure is an error, never an empty result."),
			mcp.WithString("type", mcp.Description("Finding type to search"), mcp.Enum(findings.Names()...)),
			mcp.WithString("severity", mcp.Description("Filter by severity"), mcp.Enum("critical", "high", "medium", "low")),
			mcp.WithString("status", mcp.Description("Filter by status"), mcp.Enum(findings.Statuses...)),
			mcp.WithString("repository", mcp.Description("Filter by repository name")),
			mcp.WithString("from", mcp.Description("Only findings at or after this RFC 3339 UTC time")),
			mcp.WithString("to", mcp.Description("Only findings at or before this RFC 3339 UTC time")),
			mcp.WithNumber("limit", mcp.Description("Max total findings across pages (default 100)")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			opts := findings.SearchOptions{
				Severity:   getStringArg(args, "severity"),
				Repository: getStringArg(args, "repository"),
				Status:     getStringArg(args, "status"),
				From:       getStringArg(args, "from"),
				To:         getStringArg(args, "to"),
				Limit:      getIntArg(args, "limit", 100),
			}
			if name := getStringArg(args, "type"); name != "" {
				apiTypes, err := findings.APITypesFor(name)
				if err != nil {
					return toolError(err), nil
				}
				opts.APITypes = apiTypes
			}

			result, err := findings.Search(ctx, c, opts)
			if err != nil {
				return toolError(err), nil
			}
			out, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return toolError(err), nil
			}
			return toolResult(string(out)), nil
		},
	)
}

func registerFindingEventsTool(s *server.MCPServer, c *api.Client) {
	s.AddTool(
		readOnlyTool(
			"nullify_get_finding_events",
			mcp.WithDescription("Get the event history for a finding (status changes, triage, autofix activity)."),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
			mcp.WithNumber("limit", mcp.Description("Max events (default 50)")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			limit := getIntArg(args, "limit", 50)
			out, err := c.CreateAdminEvents(ctx, api.CreateAdminEventsInput{
				FindingIds: []string{getStringArg(args, "id")},
				Limit:      &limit,
			})
			if err != nil {
				return toolError(err), nil
			}
			b, err := json.Marshal(out)
			if err != nil {
				return toolError(err), nil
			}
			return toolResult(string(b)), nil
		},
	)
}

func registerVerbTool(s *server.MCPServer, c *api.Client, verb findings.Verb) {
	options := []mcp.ToolOption{
		mcp.WithDescription(verb.Description),
		mcp.WithString("type", mcp.Required(), mcp.Description("Finding type. The type value of a search result is accepted as it is."), mcp.Enum(verb.TypeValues()...)),
		mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
	}
	if verb.NeedsAllowlistType {
		options = append(options, mcp.WithString("allowlist_type", mcp.Required(), mcp.Description("Why the finding is being allowlisted. Use UserFalsePositive when triage was wrong and UserAssumeRisk only when the risk is real and accepted."), mcp.Enum(findings.AllowlistTypes...)))
	}
	if verb.NeedsReason {
		options = append(options, mcp.WithString("reason", mcp.Required(), mcp.Description("Human-readable reason")))
	}

	newTool := readOnlyTool
	if verb.Write {
		newTool = writeTool
	}

	s.AddTool(
		newTool(verb.Tool, options...),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			return wrapRaw(verb.Run(ctx, c, getStringArg(args, "type"), getStringArg(args, "id"), findings.Params{
				Reason:        getStringArg(args, "reason"),
				AllowlistType: getStringArg(args, "allowlist_type"),
			}))
		},
	)
}

func registerFeedbackTools(s *server.MCPServer, c *api.Client) {
	s.AddTool(
		writeTool(
			"nullify_submit_finding_feedback",
			mcp.WithDescription("Record feedback on a finding of any type. This never changes the finding."),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
			mcp.WithString("verdict", mcp.Required(), mcp.Description("Feedback verdict"), mcp.Enum(findings.FeedbackVerdicts...)),
			mcp.WithString("comment", mcp.Description("Optional comment")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			return wrapRaw(findings.SubmitFeedback(ctx, c, getStringArg(args, "id"), getStringArg(args, "verdict"), getStringArg(args, "comment")))
		},
	)

	s.AddTool(
		readOnlyTool(
			"nullify_get_finding_feedback",
			mcp.WithDescription("List the feedback recorded on a finding of any type."),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return wrapRaw(findings.ListFeedback(ctx, c, getStringArg(request.GetArguments(), "id")))
		},
	)
}

func registerFixTool(s *server.MCPServer, c *api.Client) {
	s.AddTool(
		writeTool(
			"nullify_fix_finding",
			mcp.WithDescription("Start an autofix run for a finding and return at once. A run can take up to 45 minutes and opens any pull request itself. Call nullify_get_fix_status to follow the run and nullify_get_fix_diff to read its change."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Finding type"), mcp.Enum(findings.NamesWith(func(t findings.Type) bool { return t.AutofixFix != nil })...)),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			start, err := findings.StartFix(ctx, c, getStringArg(args, "type"), getStringArg(args, "id"))
			if err != nil {
				return toolError(err), nil
			}

			out, err := json.Marshal(map[string]string{"state": start.State, "run_id": start.RunID, "check_with": "nullify_get_fix_status"})
			if err != nil {
				return toolError(err), nil
			}
			return toolResult(string(out)), nil
		},
	)
}

// wrapRaw converts an API response into an MCP tool result.
func wrapRaw(data json.RawMessage, err error) (*mcp.CallToolResult, error) {
	if err != nil {
		return toolError(err), nil
	}
	return toolResult(string(data)), nil
}

// marshalOut turns a typed generated-client result into JSON.
func marshalOut[T any](out *T, err error) (json.RawMessage, error) {
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}
