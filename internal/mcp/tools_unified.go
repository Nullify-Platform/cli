package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

	// allowlistPatchStyle marks types whose allowlist endpoint is the bughunt
	// PATCH contract — body {allow, reason} — rather than the POST contract
	// {allowlistReason, allowlistType} every other type uses. See
	// hyperdrive PatchBugHuntFindingAllowlistInput vs the per-service POST inputs.
	allowlistPatchStyle bool
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
		apiTypes:            []string{"BugHunt"},
		get:                 (*api.Client).GetDastBughuntFindingsFindingId,
		triage:              (*api.Client).ListDastBughuntFindingsFindingIdTriage,
		allowlist:           (*api.Client).PatchDastBughuntFindingsFindingIdAllowlist,
		allowlistPatchStyle: true,
		// bughunt has no ticket/unallowlist/autofix; its PATCH allowlist takes
		// {allow, reason} (see allowlistPatchStyle).
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

// findingSearchOpts are the filters the unified /admin/findings search accepts.
type findingSearchOpts struct {
	apiTypes   []string // FindingType values; empty means all types
	severity   string   // lowercase enum value; uppercased for the API
	repository string   // repository name
	status     string   // open | fixed | false_positive | accepted_risk
	limit      int      // max findings to collect across pages
}

// searchFindings queries the unified POST /admin/findings endpoint, paginating
// (with a constant page size) up to opts.limit and returning the collected
// findings plus the server's reported total. This is the single place finding
// filters are mapped to the API query, so every search/composite tool stays
// consistent — in particular, `repository` and `severity` ride in the request
// body here, whereas the per-scanner GET list endpoints silently ignore them.
func searchFindings(ctx context.Context, c *api.Client, opts findingSearchOpts) ([]json.RawMessage, int, error) {
	type pageResp struct {
		Findings    []json.RawMessage `json:"findings"`
		Total       int               `json:"total"`
		HasMoreData bool              `json:"hasMoreData"`
	}
	// pageSize is chosen once per call and held constant across pages:
	// /admin/findings is page/offset paginated, so shrinking pageSize on the
	// final page would corrupt offset (page*pageSize) and skip/duplicate
	// rows. Composite tools call with limits as low as 10, so we clamp
	// instead of hard-pinning at 100 to avoid fetching 100× the rows we keep.
	pageSize := opts.limit
	if pageSize > 100 {
		pageSize = 100
	}
	if pageSize < 20 {
		pageSize = 20
	}
	all := make([]json.RawMessage, 0)
	var lastTotal int
	for page := 1; len(all) < opts.limit; page++ {
		query := map[string]any{"pageSize": pageSize, "page": page}
		if opts.repository != "" {
			query["repository"] = []string{opts.repository}
		}
		if opts.severity != "" {
			query["severity"] = []string{strings.ToUpper(opts.severity)}
		}
		if len(opts.apiTypes) > 0 {
			query["type"] = opts.apiTypes
		}
		switch opts.status {
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
			return nil, 0, err
		}
		var resp pageResp
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, 0, err
		}
		lastTotal = resp.Total
		all = append(all, resp.Findings...)
		if !resp.HasMoreData || len(resp.Findings) == 0 {
			break
		}
	}
	if len(all) > opts.limit {
		all = all[:opts.limit]
	}
	return all, lastTotal, nil
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
			opts := findingSearchOpts{
				severity:   getStringArg(args, "severity"),
				repository: getStringArg(args, "repository"),
				status:     getStringArg(args, "status"),
				limit:      getIntArg(args, "limit", 100),
			}
			if name := getStringArg(args, "type"); name != "" {
				ft, err := resolveFindingType(name)
				if err != nil {
					return toolError(err), nil
				}
				opts.apiTypes = ft.apiTypes
			}
			findings, total, err := searchFindings(ctx, c, opts)
			if err != nil {
				return toolError(err), nil
			}
			out, _ := json.MarshalIndent(map[string]any{"findings": findings, "total": total}, "", "  ")
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
			body := allowlistBody(ft, getStringArg(args, "reason"), getStringArg(args, "allowlist_type"))
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
			mcp.WithDescription("Generate an autofix for a finding: triggers the fix agent, waits for it to finish, and returns the resulting diff. Autofix runs asynchronously server-side. For finding types whose fix flow opens a pull request (e.g. sast, sca) the PR is created as part of the run; set create_pr=true to also wait for and report the resulting PR."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Finding type"), mcp.Enum(typesWith(func(ft findingType) bool { return ft.autofixFix != nil })...)),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
			mcp.WithBoolean("create_pr", mcp.Description("Wait for and report pull-request creation. The fix flow opens the PR for supported types; scpm uses a dedicated create-PR endpoint.")),
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
			// empty cache immediately. On timeout the fix may still be running
			// — return now with what we have rather than hiding the in-progress
			// state behind a "diff failed" error from the unfetched cache.
			var parts []string
			if ft.autofixState != nil {
				if _, err := pollAutofix(ctx, c, ft, params, false); err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						return toolResult("Autofix triggered but did not finish within the poll deadline; check the finding in the dashboard."), nil
					}
					return toolError(err), nil
				}
			}

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
					switch {
					case errors.Is(err, context.DeadlineExceeded):
						parts = append(parts, "--- pull request ---\nStill running after the poll deadline; check the finding in the dashboard.")
					case err != nil:
						return toolError(err), nil
					default:
						parts = append(parts, formatPRResult(st))
					}
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
// endpoint reports the fix-generation state, a server-computed `terminal` flag
// (the authoritative "stop polling" signal), and, once a PR is requested, the
// pull-request state and URL.
type autofixStatus struct {
	State            string `json:"state"`
	Terminal         bool   `json:"terminal"`
	PullRequestState string `json:"pullRequestState"`
	PullRequestURL   string `json:"pullRequestUrl"`
}

// autofixStatusResp mirrors the wire shape of every per-service autofix-status
// endpoint: the payload is wrapped under "status". See
// hyperdrive/pkg/endpoints/autofix_status_output.go — the generator preserves
// the named field rather than embedding so typed-string enums survive in the
// OpenAPI schema, which means clients must unwrap.
type autofixStatusResp struct {
	Status autofixStatus `json:"status"`
}

// autoFixStateCached is the one terminal fix-generation state that carries no
// PR ("proposed changes are available in S3 but no PR has been created").
// Mirrors models.AutoFixStateCached in hyperdrive; the generated client returns
// the raw status JSON, so we match the literal. When waiting on PR creation we
// must not stop here even though the server reports terminal=true.
const autoFixStateCached = "cached"

// allowlistBody builds the allowlist request body for a finding type. bughunt's
// PATCH endpoint takes {allow, reason}; every other type's POST endpoint takes
// {allowlistReason, allowlistType}. allowlistType has no bughunt equivalent.
func allowlistBody(ft findingType, reason, allowlistType string) []byte {
	if ft.allowlistPatchStyle {
		body, _ := json.Marshal(map[string]any{"allow": true, "reason": reason})
		return body
	}
	body, _ := json.Marshal(map[string]string{
		"allowlistReason": reason,
		"allowlistType":   allowlistType,
	})
	return body
}

// autofixPhaseDone reports whether the watched autofix phase has finished, using
// the server-computed `terminal` flag as the authority. The fix-generation phase
// is done once terminal. The PR phase is done once a PR URL exists, or the run
// reaches a terminal state other than "cached" — "cached" is terminal but means
// the fix was generated without a PR, so we keep waiting for PR creation.
func autofixPhaseDone(st autofixStatus, watchPR bool) bool {
	if watchPR {
		return st.PullRequestURL != "" || (st.Terminal && st.State != autoFixStateCached)
	}
	return st.Terminal
}

// autofixPollDeadline is the default per-call timeout for pollAutofix. Tests
// shorten it via the override hook below.
var autofixPollDeadline = 5 * time.Minute

// autofixPollInterval is the gap between polls. Tests shorten it to keep the
// timeout-path test fast.
var autofixPollInterval = 3 * time.Second

// pollAutofix polls the autofix status endpoint until the watched phase is done
// or the deadline passes. It trusts the server-computed `terminal` flag rather
// than inferring terminality from the state string. When watchPR is false it
// waits for fix generation to finish; when true it waits for PR creation (a
// non-empty pullRequestUrl, or a terminal state other than "cached", which is
// terminal but has no PR). On deadline it returns context.DeadlineExceeded so
// callers can render "still running, check the dashboard" instead of fake
// empty-PR output.
func pollAutofix(ctx context.Context, c *api.Client, ft findingType, params url.Values, watchPR bool) (autofixStatus, error) {
	deadline := time.Now().Add(autofixPollDeadline)
	var last autofixStatus
	for {
		data, err := ft.autofixState(c, ctx, params)
		if err != nil {
			return last, fmt.Errorf("poll autofix status: %w", err)
		}
		var wrapper autofixStatusResp
		if err := json.Unmarshal(data, &wrapper); err == nil {
			last = wrapper.Status
		}

		if autofixPhaseDone(last, watchPR) {
			return last, nil
		}
		if time.Now().After(deadline) {
			return last, context.DeadlineExceeded
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(autofixPollInterval):
		}
	}
}
