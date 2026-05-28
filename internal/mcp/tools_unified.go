package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/api/models"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// findingMethodGet adapts a typed no-body generated client method to a uniform
// "fetch by finding-id, return JSON bytes" shape so the per-finding-type
// dispatch table can route a single tool to the right typed endpoint.
type findingMethodGet = func(c *api.Client, ctx context.Context, findingID string) (json.RawMessage, error)

// findingMethodAction adapts a typed body-taking generated client method. The
// body is supplied as already-marshalled JSON bytes; the closure decodes them
// into the typed input struct (path/url fields are tagged json:"-" so they
// don't conflict), sets the FindingID, calls the typed method, and re-marshals
// the typed response.
type findingMethodAction = func(c *api.Client, ctx context.Context, findingID string, body []byte) (json.RawMessage, error)

// findingType bundles the typed-client capabilities for one finding-type slug.
// A nil method means the platform does not support that capability for the
// type, and the unified tool will not offer it for that type.
type findingType struct {
	apiTypes        []string // values for the /admin/findings + /admin/events "type" filter
	get             findingMethodGet
	triage          findingMethodGet // GET .../triage — AI-triage detail (read-only)
	ticket          findingMethodAction
	allowlist       findingMethodAction
	unallowlist     findingMethodAction
	autofixFix      findingMethodAction
	autofixState    findingMethodGet
	autofixDiff     findingMethodGet
	autofixCreatePR findingMethodAction

	// allowlistPatchStyle marks types whose allowlist endpoint is the bughunt
	// PATCH contract — body {allow, reason} — rather than the POST contract
	// {allowlistReason, allowlistType} every other type uses. See
	// hyperdrive PatchBugHuntFindingAllowlistInput vs the per-service POST inputs.
	allowlistPatchStyle bool
}

// marshalOut is a tiny helper that turns any (*T, error) typed-method result
// into a (json.RawMessage, error) for the adapter signature.
func marshalOut[T any](out *T, err error) (json.RawMessage, error) {
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

// rawOut passes through a ([]byte, error) result. Some endpoints have no $ref
// in their 2xx response schema, so the generator falls back to a raw-bytes
// return; this adapter avoids re-marshalling.
func rawOut(data []byte, err error) (json.RawMessage, error) {
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

// decodeBody unmarshals body bytes into a typed input struct. Empty body is
// treated as "no body fields"; the typed method's body marshal will then send
// an empty JSON object (or whatever the omitempty pattern dictates).
func decodeBody[T any](body []byte, in *T) error {
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, in)
}

var findingTypes = map[string]findingType{
	"sast": {
		apiTypes: []string{"Code"},
		get: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.GetSastFindingsFindingId(ctx, api.GetSastFindingsFindingIdInput{FindingID: id}))
		},
		triage: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListSastFindingsFindingIdTriage(ctx, api.ListSastFindingsFindingIdTriageInput{FindingID: id}))
		},
		ticket: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateSastFindingsFindingIdTicketInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return marshalOut(c.CreateSastFindingsFindingIdTicket(ctx, in))
		},
		allowlist: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateSastFindingsFindingIdAllowlistInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return marshalOut(c.CreateSastFindingsFindingIdAllowlist(ctx, in))
		},
		unallowlist: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateSastFindingsFindingIdUnallowlistInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return rawOut(c.CreateSastFindingsFindingIdUnallowlist(ctx, in))
		},
		autofixFix: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateSastFindingsFindingIdAutofixFixInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return marshalOut(c.CreateSastFindingsFindingIdAutofixFix(ctx, in))
		},
		autofixState: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListSastFindingsFindingIdAutofixStatus(ctx, api.ListSastFindingsFindingIdAutofixStatusInput{FindingID: id}))
		},
		autofixDiff: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListSastFindingsFindingIdAutofixCacheDiff(ctx, api.ListSastFindingsFindingIdAutofixCacheDiffInput{FindingID: id}))
		},
	},
	"sca_dependencies": {
		apiTypes: []string{"Dependencies"},
		get: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.GetScaDependenciesFindingsFindingId(ctx, api.GetScaDependenciesFindingsFindingIdInput{FindingID: id}))
		},
		triage: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListScaDependenciesFindingsFindingIdTriage(ctx, api.ListScaDependenciesFindingsFindingIdTriageInput{FindingID: id}))
		},
		ticket: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateScaDependenciesFindingsFindingIdTicketInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return marshalOut(c.CreateScaDependenciesFindingsFindingIdTicket(ctx, in))
		},
		allowlist: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateScaDependenciesFindingsFindingIdAllowlistInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return rawOut(c.CreateScaDependenciesFindingsFindingIdAllowlist(ctx, in))
		},
		unallowlist: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateScaDependenciesFindingsFindingIdUnallowlistInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return rawOut(c.CreateScaDependenciesFindingsFindingIdUnallowlist(ctx, in))
		},
		autofixFix: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateScaDependenciesFindingsFindingIdAutofixFixInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return marshalOut(c.CreateScaDependenciesFindingsFindingIdAutofixFix(ctx, in))
		},
		autofixState: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListScaDependenciesFindingsFindingIdAutofixStatus(ctx, api.ListScaDependenciesFindingsFindingIdAutofixStatusInput{FindingID: id}))
		},
		autofixDiff: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListScaDependenciesFindingsFindingIdAutofixCacheDiff(ctx, api.ListScaDependenciesFindingsFindingIdAutofixCacheDiffInput{FindingID: id}))
		},
	},
	"sca_containers": {
		apiTypes: []string{"Containers"},
		get: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.GetScaContainersFindingsFindingId(ctx, api.GetScaContainersFindingsFindingIdInput{FindingID: id}))
		},
		triage: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListScaContainersFindingsFindingIdTriage(ctx, api.ListScaContainersFindingsFindingIdTriageInput{FindingID: id}))
		},
		ticket: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateScaContainersFindingsFindingIdTicketInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return marshalOut(c.CreateScaContainersFindingsFindingIdTicket(ctx, in))
		},
		allowlist: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateScaContainersFindingsFindingIdAllowlistInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return rawOut(c.CreateScaContainersFindingsFindingIdAllowlist(ctx, in))
		},
		unallowlist: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateScaContainersFindingsFindingIdUnallowlistInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return rawOut(c.CreateScaContainersFindingsFindingIdUnallowlist(ctx, in))
		},
		autofixFix: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateScaContainersFindingsFindingIdAutofixFixInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return marshalOut(c.CreateScaContainersFindingsFindingIdAutofixFix(ctx, in))
		},
		autofixState: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListScaContainersFindingsFindingIdAutofixStatus(ctx, api.ListScaContainersFindingsFindingIdAutofixStatusInput{FindingID: id}))
		},
		// containers expose no cache-diff endpoint
	},
	"secrets": {
		apiTypes: []string{"SecretsCredentials", "SecretsSensitiveData"},
		get: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.GetSecretsFindingsFindingId(ctx, api.GetSecretsFindingsFindingIdInput{FindingID: id}))
		},
		triage: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListSecretsFindingsFindingIdTriage(ctx, api.ListSecretsFindingsFindingIdTriageInput{FindingID: id}))
		},
		ticket: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateSecretsFindingsFindingIdTicketInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return marshalOut(c.CreateSecretsFindingsFindingIdTicket(ctx, in))
		},
		allowlist: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateSecretsFindingsFindingIdAllowlistInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return rawOut(c.CreateSecretsFindingsFindingIdAllowlist(ctx, in))
		},
		unallowlist: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateSecretsFindingsFindingIdUnallowlistInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return rawOut(c.CreateSecretsFindingsFindingIdUnallowlist(ctx, in))
		},
		// secrets have no autofix
	},
	"pentest": {
		apiTypes: []string{"Pentest"},
		get: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.GetDastPentestFindingsFindingId(ctx, api.GetDastPentestFindingsFindingIdInput{FindingID: id}))
		},
		triage: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListDastPentestFindingsFindingIdTriage(ctx, api.ListDastPentestFindingsFindingIdTriageInput{FindingID: id}))
		},
		ticket: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateDastPentestFindingsFindingIdTicketInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return marshalOut(c.CreateDastPentestFindingsFindingIdTicket(ctx, in))
		},
		allowlist: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateDastPentestFindingsFindingIdAllowlistInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return rawOut(c.CreateDastPentestFindingsFindingIdAllowlist(ctx, in))
		},
		unallowlist: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateDastPentestFindingsFindingIdUnallowlistInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return rawOut(c.CreateDastPentestFindingsFindingIdUnallowlist(ctx, in))
		},
		autofixFix: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateDastPentestFindingsFindingIdAutofixFixInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return marshalOut(c.CreateDastPentestFindingsFindingIdAutofixFix(ctx, in))
		},
		autofixState: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListDastPentestFindingsFindingIdAutofixStatus(ctx, api.ListDastPentestFindingsFindingIdAutofixStatusInput{FindingID: id}))
		},
		autofixDiff: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListDastPentestFindingsFindingIdAutofixCacheDiff(ctx, api.ListDastPentestFindingsFindingIdAutofixCacheDiffInput{FindingID: id}))
		},
	},
	"bughunt": {
		apiTypes: []string{"BugHunt"},
		get: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.GetDastBughuntFindingsFindingId(ctx, api.GetDastBughuntFindingsFindingIdInput{FindingID: id}))
		},
		triage: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListDastBughuntFindingsFindingIdTriage(ctx, api.ListDastBughuntFindingsFindingIdTriageInput{FindingID: id}))
		},
		allowlist: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.PatchDastBughuntFindingsFindingIdAllowlistInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return marshalOut(c.PatchDastBughuntFindingsFindingIdAllowlist(ctx, in))
		},
		allowlistPatchStyle: true,
		// bughunt has no ticket/unallowlist/autofix; its PATCH allowlist takes
		// {allow, reason} (see allowlistPatchStyle).
	},
	"cspm": {
		apiTypes: []string{"Cloud"},
		get: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.GetCspmFindingsFindingId(ctx, api.GetCspmFindingsFindingIdInput{FindingID: id}))
		},
		ticket: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateCspmFindingsFindingIdTicketInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return marshalOut(c.CreateCspmFindingsFindingIdTicket(ctx, in))
		},
		autofixFix: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateCspmFindingsFindingIdAutofixFixInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return marshalOut(c.CreateCspmFindingsFindingIdAutofixFix(ctx, in))
		},
		autofixState: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListCspmFindingsFindingIdAutofixStatus(ctx, api.ListCspmFindingsFindingIdAutofixStatusInput{FindingID: id}))
		},
		autofixDiff: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListCspmFindingsFindingIdAutofixCacheDiff(ctx, api.ListCspmFindingsFindingIdAutofixCacheDiffInput{FindingID: id}))
		},
		// cspm has no events/allowlist; triage endpoint not exposed
	},
	"scpm": {
		apiTypes: []string{"Platform"},
		get: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.GetScpmFindingsFindingId(ctx, api.GetScpmFindingsFindingIdInput{FindingID: id}))
		},
		triage: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListScpmFindingsFindingIdTriage(ctx, api.ListScpmFindingsFindingIdTriageInput{FindingID: id}))
		},
		allowlist: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateScpmFindingsFindingIdAllowlistInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return marshalOut(c.CreateScpmFindingsFindingIdAllowlist(ctx, in))
		},
		unallowlist: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateScpmFindingsFindingIdUnallowlistInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return rawOut(c.CreateScpmFindingsFindingIdUnallowlist(ctx, in))
		},
		autofixFix: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateScpmFindingsFindingIdAutofixFixInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return marshalOut(c.CreateScpmFindingsFindingIdAutofixFix(ctx, in))
		},
		autofixState: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListScpmFindingsFindingIdAutofixStatus(ctx, api.ListScpmFindingsFindingIdAutofixStatusInput{FindingID: id}))
		},
		autofixDiff: func(c *api.Client, ctx context.Context, id string) (json.RawMessage, error) {
			return marshalOut(c.ListScpmFindingsFindingIdAutofixCacheDiff(ctx, api.ListScpmFindingsFindingIdAutofixCacheDiffInput{FindingID: id}))
		},
		autofixCreatePR: func(c *api.Client, ctx context.Context, id string, body []byte) (json.RawMessage, error) {
			var in api.CreateScpmFindingsFindingIdAutofixCacheCreatePrInput
			if err := decodeBody(body, &in); err != nil {
				return nil, err
			}
			in.FindingID = id
			return marshalOut(c.CreateScpmFindingsFindingIdAutofixCacheCreatePr(ctx, in))
		},
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
//
// The endpoint accepts an open-ended Query field; we keep it as a typed
// map[string]any to preserve the existing wire shape while taking advantage of
// the typed Input/Output structs around it.
func searchFindings(ctx context.Context, c *api.Client, opts findingSearchOpts) ([]json.RawMessage, int, error) {
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
		p, ps := page, pageSize
		query := models.ModelsUnifiedFindingsQuery{
			Page:     &p,
			PageSize: &ps,
		}
		if opts.repository != "" {
			query.Repository = []string{opts.repository}
		}
		if opts.severity != "" {
			query.Severity = []string{strings.ToUpper(opts.severity)}
		}
		if len(opts.apiTypes) > 0 {
			query.Type = opts.apiTypes
		}
		boolPtr := func(b bool) *bool { return &b }
		switch opts.status {
		case "open":
			query.IsResolved = boolPtr(false)
		case "fixed":
			query.IsFixed = boolPtr(true)
		case "false_positive":
			query.IsFalsePositive = boolPtr(true)
		case "accepted_risk":
			query.IsAllowlisted = boolPtr(true)
		}

		out, err := c.CreateAdminFindings(ctx, api.CreateAdminFindingsInput{Query: query})
		if err != nil {
			return nil, 0, err
		}
		lastTotal = out.Total
		// The Findings field is a typed slice of finding models; re-marshal each
		// element so callers can keep treating them as opaque JSON. (We don't
		// destructure individual finding fields here.)
		for _, f := range out.Findings {
			b, err := json.Marshal(f)
			if err != nil {
				return nil, 0, err
			}
			all = append(all, b)
		}
		if !out.HasMoreData || len(out.Findings) == 0 {
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
		findingByIDHandler(c, func(ft findingType) findingMethodGet { return ft.get }, "get"),
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

	// 3b. AI-triage detail (read-only) per finding type.
	s.AddTool(
		mcp.NewTool(
			"nullify_get_finding_triage",
			mcp.WithDescription("Get the AI-triage analysis for a finding: the model's assessment of exploitability, severity, and recommended disposition."),
			mcp.WithString("type", mcp.Required(), mcp.Description("Finding type"), mcp.Enum(typesWith(func(ft findingType) bool { return ft.triage != nil })...)),
			mcp.WithString("id", mcp.Required(), mcp.Description("Finding ID")),
		),
		findingByIDHandler(c, func(ft findingType) findingMethodGet { return ft.triage }, "triage"),
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
			return wrapRaw(ft.ticket(c, ctx, getStringArg(args, "id"), nil))
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
			body := allowlistBody(ft, getStringArg(args, "reason"), getStringArg(args, "allowlist_type"))
			return wrapRaw(ft.allowlist(c, ctx, getStringArg(args, "id"), body))
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
			body, _ := json.Marshal(map[string]string{"unallowlistReason": getStringArg(args, "reason")})
			return wrapRaw(ft.unallowlist(c, ctx, getStringArg(args, "id"), body))
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
			findingID := getStringArg(args, "id")

			if _, err := ft.autofixFix(c, ctx, findingID, nil); err != nil {
				return toolError(fmt.Errorf("trigger autofix: %w", err)), nil
			}

			// Phase 1: wait for the fix to generate. Autofix is an async
			// Step-Function/Fargate job, so we poll rather than read a possibly-
			// empty cache immediately. On timeout the fix may still be running
			// — return now with what we have rather than hiding the in-progress
			// state behind a "diff failed" error from the unfetched cache.
			var parts []string
			if ft.autofixState != nil {
				if _, err := pollAutofix(ctx, c, ft, findingID, false); err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						return toolResult("Autofix triggered but did not finish within the poll deadline; check the finding in the dashboard."), nil
					}
					return toolError(err), nil
				}
			}

			if ft.autofixDiff != nil {
				diff, err := ft.autofixDiff(c, ctx, findingID)
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
					if _, err := ft.autofixCreatePR(c, ctx, findingID, nil); err != nil {
						return toolError(fmt.Errorf("create PR: %w", err)), nil
					}
				}
				if ft.autofixState != nil {
					st, err := pollAutofix(ctx, c, ft, findingID, true)
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
func findingByIDHandler(c *api.Client, pick func(findingType) findingMethodGet, capability string) server.ToolHandlerFunc {
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
		return wrapRaw(method(c, ctx, getStringArg(args, "id")))
	}
}

// wrapRaw converts a (json.RawMessage, error) from a typed-method closure into
// an MCP tool result. The bytes are passed through verbatim as the tool's
// textual output.
func wrapRaw(data json.RawMessage, err error) (*mcp.CallToolResult, error) {
	if err != nil {
		return toolError(err), nil
	}
	return toolResult(string(data)), nil
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
func pollAutofix(ctx context.Context, c *api.Client, ft findingType, findingID string, watchPR bool) (autofixStatus, error) {
	deadline := time.Now().Add(autofixPollDeadline)
	var last autofixStatus
	for {
		data, err := ft.autofixState(c, ctx, findingID)
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
