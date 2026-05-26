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
	apiTypes        []string // values for the /admin/findings + /admin/events "type" filter
	get             methodNoBody
	triage          methodNoBody // GET .../triage — AI-triage detail (read-only)
	ticket          methodWithBody
	allowlist       methodWithBody
	unallowlist     methodWithBody
	autofixFix      methodWithBody
	autofixState    methodNoBody
	autofixDiff     methodNoBody
	autofixCreatePR methodWithBody
}

var findingTypes = map[string]findingType{
	"sast": {
		apiTypes:     []string{"Code"},
		get:          (*api.Client).GetSastFindingsFindingId,
		triage:       (*api.Client).ListSastFindingsFindingIdTriage,
		ticket:       (*api.Client).CreateSastFindingsFindingIdTicket,
		allowlist:    (*api.Client).CreateSastFindingsFindingIdAllowlist,
		unallowlist:  (*api.Client).CreateSastFindingsFindingIdUnallowlist,
		autofixFix:   (*api.Client).CreateSastFindingsFindingIdAutofixFix,
		autofixState: (*api.Client).ListSastFindingsFindingIdAutofixStatus,
		autofixDiff:  (*api.Client).ListSastFindingsFindingIdAutofixCacheDiff,
	},
	"sca_dependencies": {
		apiTypes:     []string{"Dependencies"},
		get:          (*api.Client).GetScaDependenciesFindingsFindingId,
		triage:       (*api.Client).ListScaDependenciesFindingsFindingIdTriage,
		ticket:       (*api.Client).CreateScaDependenciesFindingsFindingIdTicket,
		allowlist:    (*api.Client).CreateScaDependenciesFindingsFindingIdAllowlist,
		unallowlist:  (*api.Client).CreateScaDependenciesFindingsFindingIdUnallowlist,
		autofixFix:   (*api.Client).CreateScaDependenciesFindingsFindingIdAutofixFix,
		autofixState: (*api.Client).ListScaDependenciesFindingsFindingIdAutofixStatus,
		autofixDiff:  (*api.Client).ListScaDependenciesFindingsFindingIdAutofixCacheDiff,
	},
	"sca_containers": {
		apiTypes:     []string{"Containers"},
		get:          (*api.Client).GetScaContainersFindingsFindingId,
		triage:       (*api.Client).ListScaContainersFindingsFindingIdTriage,
		ticket:       (*api.Client).CreateScaContainersFindingsFindingIdTicket,
		allowlist:    (*api.Client).CreateScaContainersFindingsFindingIdAllowlist,
		unallowlist:  (*api.Client).CreateScaContainersFindingsFindingIdUnallowlist,
		autofixFix:   (*api.Client).CreateScaContainersFindingsFindingIdAutofixFix,
		autofixState: (*api.Client).ListScaContainersFindingsFindingIdAutofixStatus,
		// containers expose no cache-diff endpoint
	},
	"secrets": {
		apiTypes:    []string{"SecretsCredentials", "SecretsSensitiveData"},
		get:         (*api.Client).GetSecretsFindingsFindingId,
		triage:      (*api.Client).ListSecretsFindingsFindingIdTriage,
		ticket:      (*api.Client).CreateSecretsFindingsFindingIdTicket,
		allowlist:   (*api.Client).CreateSecretsFindingsFindingIdAllowlist,
		unallowlist: (*api.Client).CreateSecretsFindingsFindingIdUnallowlist,
		// secrets have no autofix
	},
	"pentest": {
		apiTypes:     []string{"Pentest"},
		get:          (*api.Client).GetDastPentestFindingsFindingId,
		triage:       (*api.Client).ListDastPentestFindingsFindingIdTriage,
		ticket:       (*api.Client).CreateDastPentestFindingsFindingIdTicket,
		allowlist:    (*api.Client).CreateDastPentestFindingsFindingIdAllowlist,
		unallowlist:  (*api.Client).CreateDastPentestFindingsFindingIdUnallowlist,
		autofixFix:   (*api.Client).CreateDastPentestFindingsFindingIdAutofixFix,
		autofixState: (*api.Client).ListDastPentestFindingsFindingIdAutofixStatus,
		autofixDiff:  (*api.Client).ListDastPentestFindingsFindingIdAutofixCacheDiff,
	},
	"bughunt": {
		apiTypes:  []string{"BugHunt"},
		get:       (*api.Client).GetDastBughuntFindingsFindingId,
		triage:    (*api.Client).ListDastBughuntFindingsFindingIdTriage,
		allowlist: (*api.Client).PatchDastBughuntFindingsFindingIdAllowlist,
		// bughunt has no ticket/unallowlist/autofix
	},
	"cspm": {
		apiTypes:     []string{"Cloud"},
		get:          (*api.Client).GetCspmFindingsFindingId,
		ticket:       (*api.Client).CreateCspmFindingsFindingIdTicket,
		autofixFix:   (*api.Client).CreateCspmFindingsFindingIdAutofixFix,
		autofixState: (*api.Client).ListCspmFindingsFindingIdAutofixStatus,
		autofixDiff:  (*api.Client).ListCspmFindingsFindingIdAutofixCacheDiff,
		// cspm has no events/allowlist; triage endpoint not exposed
	},
	"scpm": {
		apiTypes:        []string{"Platform"},
		get:             (*api.Client).GetScpmFindingsFindingId,
		triage:          (*api.Client).ListScpmFindingsFindingIdTriage,
		allowlist:       (*api.Client).CreateScpmFindingsFindingIdAllowlist,
		unallowlist:     (*api.Client).CreateScpmFindingsFindingIdUnallowlist,
		autofixFix:      (*api.Client).CreateScpmFindingsFindingIdAutofixFix,
		autofixState:    (*api.Client).ListScpmFindingsFindingIdAutofixStatus,
		autofixDiff:     (*api.Client).ListScpmFindingsFindingIdAutofixCacheDiff,
		autofixCreatePR: (*api.Client).CreateScpmFindingsFindingIdAutofixCacheCreatePr,
		// scpm has no ticket endpoint
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
					query["type"] = ft.apiTypes
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

	// 3. event history via the unified /admin/events feed (filtered by finding).
	s.AddTool(
		mcp.NewTool(
			"nullify_get_finding_events",
			mcp.WithDescription("Get the event history for a finding (status changes, triage, autofix activity)."),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
			mcp.WithNumber("limit", mcp.Description("Max events (default 50)")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			body, _ := json.Marshal(map[string]any{
				"findingIds": []string{getStringArg(args, "id")},
				"limit":      getIntArg(args, "limit", 50),
			})
			return wrap(c.CreateAdminEvents(ctx, url.Values{}, bytes.NewReader(body)))
		},
	)

	// 3b. AI-triage detail (read-only) per finding type.
	s.AddTool(
		mcp.NewTool(
			"nullify_get_finding_triage",
			mcp.WithDescription("Get the AI-triage analysis for a finding: the model's assessment of exploitability, severity, and recommended disposition."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Finding type"), mcp.Enum(typesWith(func(ft findingType) bool { return ft.triage != nil })...)),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
		),
		findingByIDHandler(c, func(ft findingType) methodNoBody { return ft.triage }, "triage"),
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

	// 7. autofix: trigger, poll to completion, return the diff, and (where a
	// create-PR endpoint exists) optionally open the pull request.
	s.AddTool(
		mcp.NewTool(
			"nullify_fix_finding",
			mcp.WithDescription("Generate an autofix for a finding: triggers the fix agent, waits for it to finish, and returns the resulting diff. Autofix runs asynchronously server-side. Set create_pr=true to also open a pull request for finding types that support it."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Finding type"), mcp.Enum(typesWith(func(ft findingType) bool { return ft.autofixFix != nil })...)),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
			mcp.WithBoolean("create_pr", mcp.Description("Open a pull request from the generated fix (only for types with a create-PR endpoint)")),
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

			// Phase 1: wait for the fix to generate. Autofix is an async
			// Step-Function/Fargate job, so we poll rather than read a possibly-
			// empty cache immediately.
			if ft.autofixState != nil {
				if _, err := pollAutofix(ctx, c, ft, params, false); err != nil {
					return toolError(err), nil
				}
			}

			var parts []string
			if ft.autofixDiff != nil {
				diff, err := ft.autofixDiff(c, ctx, params)
				if err != nil {
					return toolError(fmt.Errorf("get autofix diff: %w", err)), nil
				}
				parts = append(parts, "--- diff ---\n"+string(diff))
			}

			if createPR, _ := args["create_pr"].(bool); createPR {
				// Some types have an explicit create-PR endpoint; for the rest the
				// fix run opens the PR itself. Either way, poll PR-creation status
				// and surface the resulting URL for a complete experience.
				if ft.autofixCreatePR != nil {
					if _, err := ft.autofixCreatePR(c, ctx, params, nil); err != nil {
						return toolError(fmt.Errorf("create PR: %w", err)), nil
					}
				}
				if ft.autofixState != nil {
					st, err := pollAutofix(ctx, c, ft, params, true)
					if err != nil {
						return toolError(err), nil
					}
					parts = append(parts, formatPRResult(st))
				} else {
					parts = append(parts, "--- pull request ---\nPR requested; check the finding in the dashboard for status.")
				}
			}

			if len(parts) == 0 {
				return toolResult("Autofix triggered; no diff endpoint is available for this finding type. Check the finding in the dashboard."), nil
			}
			return toolResult(strings.Join(parts, "\n\n")), nil
		},
	)
}

// formatPRResult renders the PR phase of an autofix status for the tool output.
func formatPRResult(st autofixStatus) string {
	switch {
	case st.PullRequestURL != "":
		return "--- pull request ---\nOpened: " + st.PullRequestURL
	case st.PullRequestState != "":
		return "--- pull request ---\nState: " + st.PullRequestState + " (no URL yet; check the dashboard)"
	default:
		return "--- pull request ---\nPR creation in progress; no URL reported yet."
	}
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

// autofixStatus is the subset of the autofix/status payload we poll on. The
// endpoint reports both the fix-generation state and, once a PR is requested,
// the pull-request state and URL.
type autofixStatus struct {
	State            string `json:"state"`
	PullRequestState string `json:"pullRequestState"`
	PullRequestURL   string `json:"pullRequestUrl"`
}

func isTerminalState(s string) bool {
	s = strings.ToLower(s)
	for _, term := range []string{"complet", "success", "succeed", "done", "created", "open", "merged", "fail", "error", "cancel"} {
		if strings.Contains(s, term) {
			return true
		}
	}
	return false
}

// pollAutofix polls the autofix status endpoint until the watched phase reaches
// a terminal state or the deadline passes. When watchPR is false it waits on the
// fix-generation state; when true it waits on PR creation (a non-empty
// pullRequestUrl or terminal pullRequestState). It returns the last status seen.
func pollAutofix(ctx context.Context, c *api.Client, ft findingType, params url.Values, watchPR bool) (autofixStatus, error) {
	deadline := time.Now().Add(5 * time.Minute)
	var last autofixStatus
	for {
		data, err := ft.autofixState(c, ctx, params)
		if err != nil {
			return last, fmt.Errorf("poll autofix status: %w", err)
		}
		_ = json.Unmarshal(data, &last)

		done := isTerminalState(last.State)
		if watchPR {
			done = last.PullRequestURL != "" || isTerminalState(last.PullRequestState)
		}
		if done || time.Now().After(deadline) {
			return last, nil // on timeout, return what we have rather than erroring on a slow agent
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}
