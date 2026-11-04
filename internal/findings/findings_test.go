package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/apierror"
	"github.com/stretchr/testify/require"
)

type request struct {
	Method string
	Path   string
	Body   string
}

// fakeTransport records every request and answers from respond.
type fakeTransport struct {
	mu       sync.Mutex
	requests []request
	respond  func(call int, r request) (int, string)
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	r := request{Method: req.Method, Path: req.URL.Path, Body: string(body)}

	f.mu.Lock()
	f.requests = append(f.requests, r)
	call := len(f.requests)
	f.mu.Unlock()

	status, response := 200, "{}"
	if f.respond != nil {
		status, response = f.respond(call, r)
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header), Request: req}, nil
}

func clientFor(ft *fakeTransport) *api.Client {
	return api.NewClient("acme.nullify.ai", "tok", map[string]string{}, api.WithHTTPClient(&http.Client{Transport: ft}))
}

func verbNamed(t *testing.T, name string) Verb {
	t.Helper()
	for _, v := range Verbs {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("no verb %q", name)
	return Verb{}
}

func TestVerbRun(t *testing.T) {
	falsePositive := Params{Reason: "public by design", AllowlistType: "UserFalsePositive"}

	tests := []struct {
		name     string
		verb     string
		findType string
		id       string
		params   Params
		want     error
		requests []request
	}{
		{
			name: "cspm allowlist", verb: "allowlist", findType: "cspm", id: "f1", params: falsePositive,
			requests: []request{{"POST", "/cspm/findings/f1/allowlist", `{"allowlistReason":"public by design","allowlistType":"UserFalsePositive"}`}},
		},
		{
			name: "cspm unallowlist", verb: "unallowlist", findType: "cspm", id: "f1", params: Params{Reason: "reopen"},
			requests: []request{{"POST", "/cspm/findings/f1/unallowlist", `{"unallowlistReason":"reopen"}`}},
		},
		{
			name: "cspm archive", verb: "archive", findType: "cspm", id: "f1",
			requests: []request{{"POST", "/cspm/findings/f1/archive", `{}`}},
		},
		{
			name: "cspm unarchive", verb: "unarchive", findType: "cspm", id: "f1",
			requests: []request{{"POST", "/cspm/findings/f1/unarchive", `{}`}},
		},
		{
			name: "cspm mark false positive", verb: "mark-false-positive", findType: "cspm", id: "f1", params: Params{Reason: "public by design"},
			requests: []request{{"POST", "/cspm/findings/f1/mark-false-positive", `{"falsePositiveReason":"public by design"}`}},
		},
		{
			name: "cspm unmark false positive", verb: "unmark-false-positive", findType: "cspm", id: "f1",
			requests: []request{{"POST", "/cspm/findings/f1/unmark-false-positive", `{}`}},
		},
		{
			name: "cspm triage", verb: "triage", findType: "cspm", id: "f1",
			requests: []request{{"GET", "/cspm/findings/f1/triage", ""}},
		},
		{
			name: "cspm delete ticket", verb: "delete-ticket", findType: "cspm", id: "f1",
			requests: []request{{"DELETE", "/cspm/findings/f1/ticket", ""}},
		},
		{
			name: "scpm create ticket", verb: "create-ticket", findType: "scpm", id: "f1",
			requests: []request{{"POST", "/scpm/findings/f1/ticket", `{}`}},
		},
		{
			name: "sast allowlist keeps the POST body", verb: "allowlist", findType: "sast", id: "f1", params: falsePositive,
			requests: []request{{"POST", "/sast/findings/f1/allowlist", `{"allowlistReason":"public by design","allowlistType":"UserFalsePositive"}`}},
		},
		{
			name: "bughunt allowlist keeps the PATCH body", verb: "allowlist", findType: "bughunt", id: "f1", params: falsePositive,
			requests: []request{{"PATCH", "/dast/bughunt/findings/f1/allowlist", `{"allow":true,"reason":"public by design"}`}},
		},
		{
			name: "bughunt unallowlist sends allow false", verb: "unallowlist", findType: "bughunt", id: "f1", params: Params{Reason: "reopen"},
			requests: []request{{"PATCH", "/dast/bughunt/findings/f1/allowlist", `{"allow":false,"reason":"reopen"}`}},
		},
		{
			name: "alias reaches the same type", verb: "get", findType: "sca", id: "f1",
			requests: []request{{"GET", "/sca/dependencies/findings/f1", ""}},
		},
		{name: "allowlist without a reason", verb: "allowlist", findType: "cspm", id: "f1", params: Params{AllowlistType: "UserFixed"}, want: ErrReasonRequired},
		{name: "allowlist with a blank reason", verb: "allowlist", findType: "cspm", id: "f1", params: Params{Reason: "  ", AllowlistType: "UserFixed"}, want: ErrReasonRequired},
		{name: "allowlist without a type", verb: "allowlist", findType: "cspm", id: "f1", params: Params{Reason: "r"}, want: ErrInvalidAllowlistType},
		{name: "allowlist with the server-only AI type", verb: "allowlist", findType: "cspm", id: "f1", params: Params{Reason: "r", AllowlistType: "AI"}, want: ErrInvalidAllowlistType},
		{name: "allowlist with a retired system type", verb: "allowlist", findType: "cspm", id: "f1", params: Params{Reason: "r", AllowlistType: "RuleException"}, want: ErrInvalidAllowlistType},
		{name: "archive on a type with no route", verb: "archive", findType: "sast", id: "f1", want: ErrUnsupported},
		{name: "mark false positive on a type with no route", verb: "mark-false-positive", findType: "scpm", id: "f1", params: Params{Reason: "r"}, want: ErrUnsupported},
		{name: "unknown type", verb: "get", findType: "typo", id: "f1", want: ErrUnknownType},
		{name: "empty finding ID", verb: "get", findType: "sast", id: "", want: ErrFindingIDRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{}

			_, err := verbNamed(t, tt.verb).Run(context.Background(), clientFor(ft), tt.findType, tt.id, tt.params)

			require.ErrorIs(t, err, tt.want)
			require.Equal(t, tt.requests, ft.requests)
		})
	}
}

func TestVerbTypes(t *testing.T) {
	tests := []struct {
		verb string
		want []string
	}{
		{verb: "allowlist", want: []string{"bughunt", "cspm", "pentest", "sast", "sca_containers", "sca_dependencies", "scpm", "secrets"}},
		{verb: "unallowlist", want: []string{"bughunt", "cspm", "pentest", "sast", "sca_containers", "sca_dependencies", "scpm", "secrets"}},
		{verb: "triage", want: []string{"bughunt", "cspm", "pentest", "sast", "sca_containers", "sca_dependencies", "scpm", "secrets"}},
		{verb: "create-ticket", want: []string{"bughunt", "cspm", "pentest", "sast", "sca_containers", "sca_dependencies", "scpm", "secrets"}},
		{verb: "archive", want: []string{"cspm"}},
		{verb: "unarchive", want: []string{"cspm"}},
		{verb: "mark-false-positive", want: []string{"cspm"}},
		{verb: "unmark-false-positive", want: []string{"cspm", "scpm"}},
	}
	for _, tt := range tests {
		t.Run(tt.verb, func(t *testing.T) {
			require.Equal(t, tt.want, verbNamed(t, tt.verb).Types())
		})
	}
}

func TestAPITypesFor(t *testing.T) {
	tests := []struct {
		name string
		want []string
		err  error
	}{
		{name: "sast", want: []string{"Code"}},
		{name: "sca", want: []string{"Dependencies"}},
		{name: "dependencies", want: []string{"Dependencies"}},
		{name: "containers", want: []string{"Containers"}},
		{name: "secrets", want: []string{"SecretsCredentials", "SecretsSensitiveData"}},
		{name: "bughunt", want: []string{"BugHunt"}},
		{name: "cspm", want: []string{"Cloud"}},
		{name: "scpm", want: []string{"SupplyChain"}},
		{name: "Cloud", want: []string{"Cloud"}},
		{name: "SupplyChain", want: []string{"SupplyChain"}},
		{name: "typo", err: ErrUnknownType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := APITypesFor(tt.name)

			require.ErrorIs(t, err, tt.err)
			require.Equal(t, tt.want, got)
		})
	}
}

func page(findings, total int, hasMore bool) string {
	items := make([]string, findings)
	for i := range items {
		items[i] = "{}"
	}
	return fmt.Sprintf(`{"findings":[%s],"total":%d,"hasMoreData":%t,"page":1}`, strings.Join(items, ","), total, hasMore)
}

func TestSearchReportsCompleteness(t *testing.T) {
	tests := []struct {
		name         string
		opts         SearchOptions
		pages        []string
		wantErr      error
		wantTotal    int
		wantReturned int
		truncated    bool
		wantCalls    int
	}{
		{
			name: "empty result", opts: SearchOptions{Limit: 100},
			pages: []string{page(0, 0, false)}, wantCalls: 1,
		},
		{
			name: "complete result", opts: SearchOptions{Limit: 100},
			pages: []string{page(3, 3, false)}, wantTotal: 3, wantReturned: 3, wantCalls: 1,
		},
		{
			name: "stopped at the limit", opts: SearchOptions{Limit: 150},
			pages: []string{page(100, 400, true), page(100, 400, true)}, wantTotal: 400, wantReturned: 150, truncated: true, wantCalls: 2,
		},
		{
			name: "server promises more but returns nothing", opts: SearchOptions{Limit: 100},
			pages: []string{page(20, 40, true), page(0, 40, true)}, wantTotal: 40, wantReturned: 20, truncated: true, wantCalls: 2,
		},
		{name: "a zero limit is rejected", opts: SearchOptions{Limit: 0}, wantErr: ErrInvalidLimit},
		{name: "a negative limit is rejected", opts: SearchOptions{Limit: -1}, wantErr: ErrInvalidLimit},
		{name: "an unknown status is rejected", opts: SearchOptions{Limit: 10, Status: "allowlisted"}, wantErr: ErrInvalidStatus},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{respond: func(call int, _ request) (int, string) {
				return 200, tt.pages[call-1]
			}}

			got, err := Search(context.Background(), clientFor(ft), tt.opts)

			require.ErrorIs(t, err, tt.wantErr)
			require.Equal(t, tt.wantTotal, got.Total)
			require.Equal(t, tt.wantReturned, got.Returned)
			require.Len(t, got.Findings, tt.wantReturned)
			require.Equal(t, tt.truncated, got.Truncated)
			require.Len(t, ft.requests, tt.wantCalls)
		})
	}
}

func TestSearchReturnsNoAccessAsAnError(t *testing.T) {
	ft := &fakeTransport{respond: func(int, request) (int, string) { return 403, `{"error":"forbidden"}` }}

	got, err := Search(context.Background(), clientFor(ft), SearchOptions{Limit: 100})

	var apiErr *apierror.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, 403, apiErr.StatusCode)
	require.Empty(t, got.Findings)
}

func TestSearchSendsFilters(t *testing.T) {
	yes, no := true, false

	tests := []struct {
		name string
		opts SearchOptions
		want map[string]any
	}{
		{
			name: "cspm with a UTC window",
			opts: SearchOptions{Limit: 40, APITypes: []string{"Cloud"}, From: "2026-11-01T00:00:00Z", To: "2026-11-02T00:00:00Z"},
			want: map[string]any{"page": 1.0, "pageSize": 40.0, "type": []any{"Cloud"}, "fromDate": "2026-11-01T00:00:00Z", "toDate": "2026-11-02T00:00:00Z"},
		},
		{
			name: "severity is sent upper-case with repository",
			opts: SearchOptions{Limit: 10, Severity: "critical", Repository: "my-repo"},
			want: map[string]any{"page": 1.0, "pageSize": 20.0, "severity": []any{"CRITICAL"}, "repository": []any{"my-repo"}},
		},
		{name: "open", opts: SearchOptions{Limit: 500, Status: "open"}, want: map[string]any{"page": 1.0, "pageSize": 100.0, "isResolved": no}},
		{name: "fixed", opts: SearchOptions{Limit: 100, Status: "fixed"}, want: map[string]any{"page": 1.0, "pageSize": 100.0, "isFixed": yes}},
		{name: "false positive", opts: SearchOptions{Limit: 100, Status: "false_positive"}, want: map[string]any{"page": 1.0, "pageSize": 100.0, "isFalsePositive": yes}},
		{name: "accepted risk", opts: SearchOptions{Limit: 100, Status: "accepted_risk"}, want: map[string]any{"page": 1.0, "pageSize": 100.0, "isAllowlisted": yes}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{respond: func(int, request) (int, string) { return 200, page(0, 0, false) }}

			_, err := Search(context.Background(), clientFor(ft), tt.opts)

			require.ErrorIs(t, err, nil)
			var body struct {
				Query map[string]any `json:"query"`
			}
			require.NoError(t, json.Unmarshal([]byte(ft.requests[0].Body), &body))
			require.Equal(t, tt.want, body.Query)
		})
	}
}

func TestSearchKeepsPageSizeConstantAcrossPages(t *testing.T) {
	ft := &fakeTransport{respond: func(int, request) (int, string) { return 200, page(100, 1000, true) }}

	got, err := Search(context.Background(), clientFor(ft), SearchOptions{Limit: 250})

	require.ErrorIs(t, err, nil)
	require.Equal(t, 250, got.Returned)
	require.Len(t, ft.requests, 3)
	for i, r := range ft.requests {
		require.Contains(t, r.Body, `"pageSize":100`)
		require.Contains(t, r.Body, fmt.Sprintf(`"page":%d`, i+1))
	}
}

func TestFeedback(t *testing.T) {
	tests := []struct {
		name     string
		run      func(context.Context, *api.Client) (json.RawMessage, error)
		want     error
		requests []request
	}{
		{
			name: "submit with a comment",
			run: func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
				return SubmitFeedback(ctx, c, "f1", "wrong", "not reachable")
			},
			requests: []request{{"POST", "/findings/f1/feedback", `{"commentText":"not reachable","verdict":"wrong"}`}},
		},
		{
			name: "submit without a comment",
			run: func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
				return SubmitFeedback(ctx, c, "f1", "up", "")
			},
			requests: []request{{"POST", "/findings/f1/feedback", `{"verdict":"up"}`}},
		},
		{
			name: "an unknown verdict is rejected",
			run: func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
				return SubmitFeedback(ctx, c, "f1", "meh", "")
			},
			want: ErrInvalidVerdict,
		},
		{
			name: "submit needs a finding",
			run: func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
				return SubmitFeedback(ctx, c, "", "up", "")
			},
			want: ErrFindingIDRequired,
		},
		{
			name: "list",
			run: func(ctx context.Context, c *api.Client) (json.RawMessage, error) {
				return ListFeedback(ctx, c, "f1")
			},
			requests: []request{{"GET", "/findings/f1/feedback", ""}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{}

			_, err := tt.run(context.Background(), clientFor(ft))

			require.ErrorIs(t, err, tt.want)
			require.Equal(t, tt.requests, ft.requests)
		})
	}
}

func TestAutofixPhaseDone(t *testing.T) {
	tests := []struct {
		name    string
		st      AutofixStatus
		watchPR bool
		want    bool
	}{
		{"agent in progress", AutofixStatus{State: "in_progress_agent"}, false, false},
		{"cached is terminal for fix", AutofixStatus{State: "cached", Terminal: true}, false, true},
		{"pending_review terminal for fix", AutofixStatus{State: "pending_review", Terminal: true}, false, true},
		{"failed_retry not terminal", AutofixStatus{State: "failed_retry"}, false, false},
		{"cached without PR keeps waiting", AutofixStatus{State: "cached", Terminal: true}, true, false},
		{"cached with PR url done", AutofixStatus{State: "cached", Terminal: true, PullRequestURL: "http://pr"}, true, true},
		{"pending_review with url done", AutofixStatus{State: "pending_review", Terminal: true, PullRequestURL: "http://pr"}, true, true},
		{"pr_merged terminal done", AutofixStatus{State: "pr_merged", Terminal: true}, true, true},
		{"failed_pr_creation done", AutofixStatus{State: "failed_pr_creation", Terminal: true}, true, true},
		{"creating_pr still waiting", AutofixStatus{State: "in_progress_creating_pr"}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, autofixPhaseDone(tt.st, tt.watchPR))
		})
	}
}

func TestFix(t *testing.T) {
	const terminal = `{"status":{"state":"cached","terminal":true,"pullRequestUrl":"http://pr"}}`

	tests := []struct {
		name     string
		findType string
		createPR bool
		want     error
		routes   []string
		diff     bool
		pr       *PullRequestStatus
	}{
		{
			name: "sast reads the diff", findType: "sast",
			routes: []string{"POST /sast/findings/f1/autofix/fix", "GET /sast/findings/f1/autofix/status", "GET /sast/findings/f1/autofix/cache/diff"},
			diff:   true,
		},
		{
			name: "sca alias reads the dependency diff and reports the pull request", findType: "sca", createPR: true,
			routes: []string{
				"POST /sca/dependencies/findings/f1/autofix/fix",
				"GET /sca/dependencies/findings/f1/autofix/status",
				"GET /sca/dependencies/findings/f1/autofix/cache/diff",
				"GET /sca/dependencies/findings/f1/autofix/status",
			},
			diff: true,
			pr:   &PullRequestStatus{URL: "http://pr"},
		},
		{
			name: "cspm has no diff route", findType: "cspm",
			routes: []string{"POST /cspm/findings/f1/autofix/fix", "GET /cspm/findings/f1/autofix/status"},
		},
		{
			name: "scpm has no diff or create-PR route", findType: "scpm", createPR: true,
			routes: []string{"POST /scpm/findings/f1/autofix/fix", "GET /scpm/findings/f1/autofix/status", "GET /scpm/findings/f1/autofix/status"},
			pr:     &PullRequestStatus{URL: "http://pr"},
		},
		{name: "secrets has no autofix", findType: "secrets", want: ErrUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{respond: func(_ int, r request) (int, string) {
				return 200, map[bool]string{true: terminal, false: `{}`}[strings.HasSuffix(r.Path, "/status")]
			}}

			got, err := Fix(context.Background(), clientFor(ft), tt.findType, "f1", tt.createPR)

			require.ErrorIs(t, err, tt.want)
			var routes []string
			for _, r := range ft.requests {
				routes = append(routes, r.Method+" "+r.Path)
			}
			require.Equal(t, tt.routes, routes)
			require.Equal(t, tt.diff, len(got.Diff) > 0)
			require.Equal(t, tt.pr, got.PullRequest)
		})
	}
}

func TestFixReportsStillRunningAtTheDeadline(t *testing.T) {
	t.Cleanup(func() {
		autofixPollDeadline = 5 * time.Minute
		autofixPollInterval = 3 * time.Second
	})
	autofixPollDeadline = 50 * time.Millisecond
	autofixPollInterval = 5 * time.Millisecond

	ft := &fakeTransport{respond: func(int, request) (int, string) {
		return 200, `{"status":{"state":"in_progress_agent","terminal":false}}`
	}}

	got, err := Fix(context.Background(), clientFor(ft), "sast", "f1", false)

	require.ErrorIs(t, err, nil)
	require.True(t, got.StillRunning)
}
