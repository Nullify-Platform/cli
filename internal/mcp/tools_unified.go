package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nullify-platform/cli/internal/api"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// methodNoBody / methodWithBody are the two shapes of generated api.Client
// methods, captured as method expressions so the per-type dispatch table can
// route a unified tool to the right typed endpoint.
type methodNoBody = func(*api.Client, context.Context, url.Values) ([]byte, error)
type methodWithBody = func(*api.Client, context.Context, url.Values, io.Reader) ([]byte, error)

// findingType maps a CLI finding-type slug to its api.Client methods. A nil
// method means the platform does not support that capability for the type, and
// the unified tool will not offer it for that type.
type findingType struct {
	apiType      string // value for the /admin/findings "type" filter
	get          methodNoBody
	events       methodNoBody
	ticket       methodWithBody
	allowlist    methodWithBody
	unallowlist  methodWithBody
	autofixFix   methodWithBody
	autofixState methodNoBody
	autofixDiff  methodNoBody
}

var findingTypes = map[string]findingType{
	"sast": {
		apiType:      "Code",
		get:          (*api.Client).GetSastFindingsFindingId,
		events:       (*api.Client).ListSastFindingsFindingIdEvents,
		ticket:       (*api.Client).CreateSastFindingsFindingIdTicket,
		allowlist:    (*api.Client).CreateSastFindingsFindingIdAllowlist,
		unallowlist:  (*api.Client).CreateSastFindingsFindingIdUnallowlist,
		autofixFix:   (*api.Client).CreateSastFindingsFindingIdAutofixFix,
		autofixState: (*api.Client).ListSastFindingsFindingIdAutofixStatus,
		autofixDiff:  (*api.Client).ListSastFindingsFindingIdAutofixCacheDiff,
	},
	"sca_dependencies": {
		apiType:      "Dependencies",
		get:          (*api.Client).GetScaDependenciesFindingsFindingId,
		events:       (*api.Client).ListScaDependenciesFindingsFindingIdEvents,
		ticket:       (*api.Client).CreateScaDependenciesFindingsFindingIdTicket,
		allowlist:    (*api.Client).CreateScaDependenciesFindingsFindingIdAllowlist,
		unallowlist:  (*api.Client).CreateScaDependenciesFindingsFindingIdUnallowlist,
		autofixFix:   (*api.Client).CreateScaDependenciesFindingsFindingIdAutofixFix,
		autofixState: (*api.Client).ListScaDependenciesFindingsFindingIdAutofixStatus,
		autofixDiff:  (*api.Client).ListScaDependenciesFindingsFindingIdAutofixCacheDiff,
	},
	"sca_containers": {
		apiType:      "Containers",
		get:          (*api.Client).GetScaContainersFindingsFindingId,
		events:       (*api.Client).ListScaContainersFindingsFindingIdEvents,
		ticket:       (*api.Client).CreateScaContainersFindingsFindingIdTicket,
		allowlist:    (*api.Client).CreateScaContainersFindingsFindingIdAllowlist,
		unallowlist:  (*api.Client).CreateScaContainersFindingsFindingIdUnallowlist,
		autofixFix:   (*api.Client).CreateScaContainersFindingsFindingIdAutofixFix,
		autofixState: (*api.Client).ListScaContainersFindingsFindingIdAutofixStatus,
		// containers expose no cache-diff endpoint
	},
	"secrets": {
		apiType:     "Secrets",
		get:         (*api.Client).GetSecretsFindingsFindingId,
		events:      (*api.Client).ListSecretsFindingsFindingIdEvents,
		ticket:      (*api.Client).CreateSecretsFindingsFindingIdTicket,
		allowlist:   (*api.Client).CreateSecretsFindingsFindingIdAllowlist,
		unallowlist: (*api.Client).CreateSecretsFindingsFindingIdUnallowlist,
		// secrets have no autofix
	},
	"pentest": {
		apiType:      "Pentest",
		get:          (*api.Client).GetDastPentestFindingsFindingId,
		events:       (*api.Client).ListDastPentestFindingsFindingIdEvents,
		ticket:       (*api.Client).CreateDastPentestFindingsFindingIdTicket,
		allowlist:    (*api.Client).CreateDastPentestFindingsFindingIdAllowlist,
		unallowlist:  (*api.Client).CreateDastPentestFindingsFindingIdUnallowlist,
		autofixFix:   (*api.Client).CreateDastPentestFindingsFindingIdAutofixFix,
		autofixState: (*api.Client).ListDastPentestFindingsFindingIdAutofixStatus,
		autofixDiff:  (*api.Client).ListDastPentestFindingsFindingIdAutofixCacheDiff,
	},
	"bughunt": {
		apiType:   "BugHunting",
		get:       (*api.Client).GetDastBughuntFindingsFindingId,
		events:    (*api.Client).ListDastBughuntFindingsFindingIdEvents,
		allowlist: (*api.Client).PatchDastBughuntFindingsFindingIdAllowlist,
		// bughunt has no ticket/unallowlist/autofix
	},
	"cspm": {
		apiType:      "Cloud",
		get:          (*api.Client).GetCspmFindingsFindingId,
		ticket:       (*api.Client).CreateCspmFindingsFindingIdTicket,
		autofixFix:   (*api.Client).CreateCspmFindingsFindingIdAutofixFix,
		autofixState: (*api.Client).ListCspmFindingsFindingIdAutofixStatus,
		autofixDiff:  (*api.Client).ListCspmFindingsFindingIdAutofixCacheDiff,
		// cspm has no events/allowlist
	},
}

func allFindingTypeNames() []string {
	names := make([]string, 0, len(findingTypes))
	for name := range findingTypes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// typesWith returns the sorted type slugs for which pick reports a supported
// capability, used to scope a tool's `type` enum to what actually works.
func typesWith(pick func(findingType) bool) []string {
	var names []string
	for name, ft := range findingTypes {
		if pick(ft) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func resolveFindingType(name string) (findingType, error) {
	ft, ok := findingTypes[name]
	if !ok {
		return findingType{}, fmt.Errorf("unknown finding type %q. Valid types: %s", name, strings.Join(allFindingTypeNames(), ", "))
	}
	return ft, nil
}

func registerUnifiedTools(s *server.MCPServer, c *api.Client) {
	allTypes := allFindingTypeNames()

	// 1. search across all/one type via the unified /admin/findings endpoint.
	s.AddTool(
		mcp.NewTool(
			"nullify_search_findings",
			mcp.WithDescription("Search security findings across all or a specific scanner type. Paginates automatically up to limit."),
			mcp.WithString("type", mcp.Description("Finding type to search"), mcp.Enum(allTypes...)),
			mcp.WithString("severity", mcp.Description("Filter by severity"), mcp.Enum("critical", "high", "medium", "low")),
			mcp.WithString("status", mcp.Description("Filter by status"), mcp.Enum("open", "fixed", "false_positive", "accepted_risk")),
			mcp.WithString("repository", mcp.Description("Filter by repository name")),
			mcp.WithNumber("limit", mcp.Description("Max total findings across pages (default 100)")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			limit := getIntArg(args, "limit", 100)

			type pageResp struct {
				Findings    []json.RawMessage `json:"findings"`
				Total       int               `json:"total"`
				HasMoreData bool              `json:"hasMoreData"`
			}

			all := make([]json.RawMessage, 0)
			var lastTotal int
			for page := 1; len(all) < limit; page++ {
				pageSize := 100
				if rem := limit - len(all); rem < pageSize {
					pageSize = rem
				}
				query := map[string]any{"pageSize": pageSize, "page": page}
				if v := getStringArg(args, "repository"); v != "" {
					query["repository"] = []string{v}
				}
				if v := getStringArg(args, "severity"); v != "" {
					query["severity"] = []string{strings.ToUpper(v)}
				}
				if name := getStringArg(args, "type"); name != "" {
					ft, err := resolveFindingType(name)
					if err != nil {
						return toolError(err), nil
					}
					query["type"] = []string{ft.apiType}
				}
				switch getStringArg(args, "status") {
				case "open":
					query["isResolved"] = false
				case "fixed":
					query["isFixed"] = true
				case "false_positive":
					query["isFalsePositive"] = true
				case "accepted_risk":
					query["isAllowlisted"] = true
				}

				body, _ := json.Marshal(map[string]any{"query": query})
				data, err := c.CreateAdminFindings(ctx, url.Values{}, bytes.NewReader(body))
				if err != nil {
					return toolError(err), nil
				}
				var resp pageResp
				if err := json.Unmarshal(data, &resp); err != nil {
					return toolError(err), nil
				}
				lastTotal = resp.Total
				all = append(all, resp.Findings...)
				if !resp.HasMoreData || len(resp.Findings) == 0 {
					break
				}
			}
			if len(all) > limit {
				all = all[:limit]
			}
			out, _ := json.MarshalIndent(map[string]any{"findings": all, "total": lastTotal}, "", "  ")
			return toolResult(string(out)), nil
		},
	)

	// 2. get one finding.
	s.AddTool(
		mcp.NewTool(
			"nullify_get_finding",
			mcp.WithDescription("Get details of a specific finding by type and ID."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Finding type"), mcp.Enum(allTypes...)),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
		),
		findingByIDHandler(c, func(ft findingType) methodNoBody { return ft.get }, "get"),
	)

	// 3. event history.
	s.AddTool(
		mcp.NewTool(
			"nullify_get_finding_events",
			mcp.WithDescription("Get the event history for a finding."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Finding type"), mcp.Enum(typesWith(func(ft findingType) bool { return ft.events != nil })...)),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
		),
		findingByIDHandler(c, func(ft findingType) methodNoBody { return ft.events }, "events"),
	)

	// 4. create a ticket.
	s.AddTool(
		mcp.NewTool(
			"nullify_create_ticket",
			mcp.WithDescription("Create a ticket (e.g. Jira, GitHub issue) for a finding."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Finding type"), mcp.Enum(typesWith(func(ft findingType) bool { return ft.ticket != nil })...)),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			ft, err := resolveFindingType(getStringArg(args, "type"))
			if err != nil {
				return toolError(err), nil
			}
			if ft.ticket == nil {
				return toolError(fmt.Errorf("ticketing is not supported for type %q", getStringArg(args, "type"))), nil
			}
			params := url.Values{}
			params.Set("findingId", getStringArg(args, "id"))
			return wrap(ft.ticket(c, ctx, params, nil))
		},
	)

	// 5. allowlist (suppress: fixed / accepted-risk / false-positive / other).
	s.AddTool(
		mcp.NewTool(
			"nullify_allowlist_finding",
			mcp.WithDescription("Allowlist a finding: suppress it as fixed, accepted risk, false positive, or other. This is how a finding is triaged out of the open queue."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Finding type"), mcp.Enum(typesWith(func(ft findingType) bool { return ft.allowlist != nil })...)),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
			mcp.WithString("allowlist_type", mcp.Required(), mcp.Description("Why the finding is being allowlisted"), mcp.Enum("UserFixed", "UserAssumeRisk", "UserFalsePositive", "UserOther")),
			mcp.WithString("reason", mcp.Required(), mcp.Description("Human-readable reason")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			ft, err := resolveFindingType(getStringArg(args, "type"))
			if err != nil {
				return toolError(err), nil
			}
			if ft.allowlist == nil {
				return toolError(fmt.Errorf("allowlisting is not supported for type %q", getStringArg(args, "type"))), nil
			}
			params := url.Values{}
			params.Set("findingId", getStringArg(args, "id"))
			body, _ := json.Marshal(map[string]string{
				"allowlistReason": getStringArg(args, "reason"),
				"allowlistType":   getStringArg(args, "allowlist_type"),
			})
			return wrap(ft.allowlist(c, ctx, params, bytes.NewReader(body)))
		},
	)

	// 6. unallowlist (re-open a suppressed finding).
	s.AddTool(
		mcp.NewTool(
			"nullify_unallowlist_finding",
			mcp.WithDescription("Remove a finding from the allowlist, re-opening it."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Finding type"), mcp.Enum(typesWith(func(ft findingType) bool { return ft.unallowlist != nil })...)),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
			mcp.WithString("reason", mcp.Required(), mcp.Description("Human-readable reason for re-opening")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			ft, err := resolveFindingType(getStringArg(args, "type"))
			if err != nil {
				return toolError(err), nil
			}
			if ft.unallowlist == nil {
				return toolError(fmt.Errorf("unallowlisting is not supported for type %q", getStringArg(args, "type"))), nil
			}
			params := url.Values{}
			params.Set("findingId", getStringArg(args, "id"))
			body, _ := json.Marshal(map[string]string{"unallowlistReason": getStringArg(args, "reason")})
			return wrap(ft.unallowlist(c, ctx, params, bytes.NewReader(body)))
		},
	)

	// 7. autofix: trigger, poll to completion, return the diff.
	s.AddTool(
		mcp.NewTool(
			"nullify_fix_finding",
			mcp.WithDescription("Generate an autofix for a finding. Triggers the fix agent, waits for it to finish, and returns the resulting diff. Autofix runs asynchronously server-side."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Finding type"), mcp.Enum(typesWith(func(ft findingType) bool { return ft.autofixFix != nil })...)),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			ft, err := resolveFindingType(getStringArg(args, "type"))
			if err != nil {
				return toolError(err), nil
			}
			if ft.autofixFix == nil {
				return toolError(fmt.Errorf("autofix is not supported for type %q", getStringArg(args, "type"))), nil
			}
			params := url.Values{}
			params.Set("findingId", getStringArg(args, "id"))

			if _, err := ft.autofixFix(c, ctx, params, nil); err != nil {
				return toolError(fmt.Errorf("trigger autofix: %w", err)), nil
			}

			// Poll status until the agent reaches a terminal state. Autofix is an
			// async Step-Function/Fargate job, so we must wait rather than read a
			// possibly-empty cache immediately.
			if ft.autofixState != nil {
				if err := pollAutofix(ctx, c, ft, params); err != nil {
					return toolError(err), nil
				}
			}

			if ft.autofixDiff == nil {
				return toolResult("Autofix triggered. No diff endpoint is available for this finding type; check the finding in the dashboard."), nil
			}
			return wrap(ft.autofixDiff(c, ctx, params))
		},
	)
}

// findingByIDHandler builds a handler for a no-body, by-ID finding method.
func findingByIDHandler(c *api.Client, pick func(findingType) methodNoBody, capability string) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := request.GetArguments()
		ft, err := resolveFindingType(getStringArg(args, "type"))
		if err != nil {
			return toolError(err), nil
		}
		method := pick(ft)
		if method == nil {
			return toolError(fmt.Errorf("%s is not supported for type %q", capability, getStringArg(args, "type"))), nil
		}
		params := url.Values{}
		params.Set("findingId", getStringArg(args, "id"))
		return wrap(method(c, ctx, params))
	}
}

// pollAutofix polls the autofix status endpoint until it reports a terminal
// state or the deadline passes.
func pollAutofix(ctx context.Context, c *api.Client, ft findingType, params url.Values) error {
	deadline := time.Now().Add(3 * time.Minute)
	for {
		data, err := ft.autofixState(c, ctx, params)
		if err != nil {
			return fmt.Errorf("poll autofix status: %w", err)
		}
		lower := strings.ToLower(string(data))
		if strings.Contains(lower, "complet") || strings.Contains(lower, "success") ||
			strings.Contains(lower, "fail") || strings.Contains(lower, "error") {
			return nil
		}
		if time.Now().After(deadline) {
			return nil // return whatever diff exists rather than erroring on a slow agent
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}
