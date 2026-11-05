package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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
		{verb: "allowlist", want: []string{"bughunt", "cspm", "pentest", "sast", "sca_containers", "sca_dependencies", "scpm", "secrets", "secrets_sensitive_data"}},
		{verb: "unallowlist", want: []string{"bughunt", "cspm", "pentest", "sast", "sca_containers", "sca_dependencies", "scpm", "secrets", "secrets_sensitive_data"}},
		{verb: "triage", want: []string{"bughunt", "cspm", "pentest", "sast", "sca_containers", "sca_dependencies", "scpm", "secrets", "secrets_sensitive_data"}},
		{verb: "create-ticket", want: []string{"bughunt", "cspm", "pentest", "sast", "sca_containers", "sca_dependencies", "scpm", "secrets", "secrets_sensitive_data"}},
		{verb: "fix-status", want: []string{"cspm", "pentest", "sast", "sca_containers", "sca_dependencies", "scpm"}},
		{verb: "fix-diff", want: []string{"sast", "sca_dependencies"}},
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
		{name: "sca", want: []string{"Dependencies", "Containers"}},
		{name: "dependencies", want: []string{"Dependencies"}},
		{name: "containers", want: []string{"Containers"}},
		{name: "secrets", want: []string{"SecretsCredentials", "SecretsSensitiveData"}},
		{name: "secrets_sensitive_data", want: []string{"SecretsSensitiveData"}},
		{name: "SecretsSensitiveData", want: []string{"SecretsSensitiveData"}},
		{name: "SecretsCredentials", want: []string{"SecretsCredentials"}},
		{name: "secrets_credentials", want: []string{"SecretsCredentials"}},
		{name: "Platform", want: []string{"SupplyChain"}},
		{name: "Unknown", err: ErrUnknownType},
		{name: "dast_bughunt", want: []string{"BugHunt"}},
		{name: "dast_pentest", want: []string{"Pentest"}},
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

func TestSearchKeepsRowsAsSent(t *testing.T) {
	tests := []struct {
		name string
		row  string
	}{
		{name: "a short row gains no fields", row: `{"id":"f1","type":"Code","severity":"HIGH","title":"t","repository":"r"}`},
		{name: "a field the models do not have stays", row: `{"id":"f1","addedLater":{"a":[1,2]}}`},
		{name: "a field of a changed type does not fail the list", row: `{"id":"f1","isFalsePositive":"no","createdAt":12}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{respond: func(int, request) (int, string) {
				return 200, `{"findings":[` + tt.row + `],"total":1,"hasMoreData":false}`
			}}

			got, err := Search(context.Background(), clientFor(ft), SearchOptions{Limit: 10})

			require.ErrorIs(t, err, nil)
			require.Equal(t, tt.row, string(got.Findings[0]))
		})
	}
}

func TestSearchRejectsAnUnreadableResponse(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "no findings field", body: `{}`},
		{name: "a null findings field", body: `{"findings":null,"total":0}`},
		{name: "findings is not a list", body: `{"findings":{},"total":0}`},
		{name: "not JSON", body: `<html></html>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{respond: func(int, request) (int, string) { return 200, tt.body }}

			_, err := Search(context.Background(), clientFor(ft), SearchOptions{Limit: 10})

			require.ErrorIs(t, err, ErrUnreadableResponse)
		})
	}
}

func TestHasRepository(t *testing.T) {
	tests := []struct {
		name     string
		apiTypes []string
		want     bool
	}{
		{name: "every type", want: true},
		{name: "code", apiTypes: []string{"Code"}, want: true},
		{name: "pentest", apiTypes: []string{"Pentest"}, want: true},
		{name: "sensitive data", apiTypes: []string{"SecretsSensitiveData"}, want: true},
		{name: "cloud", apiTypes: []string{"Cloud"}},
		{name: "bug hunt", apiTypes: []string{"BugHunt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, HasRepository(tt.apiTypes))
		})
	}
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
		{name: "a plain from date is rejected", opts: SearchOptions{Limit: 10, From: "2026-11-01"}, wantErr: ErrInvalidTime},
		{name: "a plain to date is rejected", opts: SearchOptions{Limit: 10, To: "2026-11-01"}, wantErr: ErrInvalidTime},
		{name: "a to time with a space is rejected", opts: SearchOptions{Limit: 10, To: "2026-11-01 10:00:00"}, wantErr: ErrInvalidTime},
		{name: "words are rejected", opts: SearchOptions{Limit: 10, From: "yesterday"}, wantErr: ErrInvalidTime},
		{name: "RFC 3339 with an offset is accepted", opts: SearchOptions{Limit: 10, From: "2026-11-01T00:00:00+10:00"}, pages: []string{page(0, 0, false)}, wantCalls: 1},
		{name: "fractional seconds are accepted", opts: SearchOptions{Limit: 10, To: "2026-11-01T00:00:00.5Z"}, pages: []string{page(0, 0, false)}, wantCalls: 1},
		{name: "a time with no zone is accepted, as on the server", opts: SearchOptions{Limit: 10, To: "2026-11-01T00:00:00"}, pages: []string{page(0, 0, false)}, wantCalls: 1},
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
		{
			name: "a full repository name also sends the bare name that most findings hold",
			opts: SearchOptions{Limit: 10, Repository: "my-org/my-repo"},
			want: map[string]any{"page": 1.0, "pageSize": 20.0, "repository": []any{"my-org/my-repo", "my-repo"}},
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
	newPR := []AutofixPullRequest{{URL: "http://new"}, {URL: "http://old"}}
	oldPR := []AutofixPullRequest{{URL: "http://old"}}
	earlier := []string{"http://old"}

	tests := []struct {
		name    string
		st      AutofixStatus
		watchPR bool
		want    bool
	}{
		{"agent in progress", AutofixStatus{State: "in_progress_agent"}, false, false},
		{"cached is terminal for fix", AutofixStatus{State: "cached", Terminal: true}, false, true},
		{"pending_review terminal for fix", AutofixStatus{State: "pending_review", Terminal: true}, false, true},
		{"failed_retry is terminal for fix", AutofixStatus{State: "failed_retry", Terminal: true}, false, true},
		{"cached without PR keeps waiting", AutofixStatus{State: "cached", Terminal: true}, true, false},
		{"cached with an earlier PR keeps waiting", AutofixStatus{State: "cached", Terminal: true, PullRequests: oldPR}, true, false},
		{"cached with a new PR is done", AutofixStatus{State: "cached", Terminal: true, PullRequests: newPR}, true, true},
		{"new PR ends the wait before terminal", AutofixStatus{State: "in_progress_draft", PullRequests: newPR}, true, true},
		{"pr_merged terminal done", AutofixStatus{State: "pr_merged", Terminal: true}, true, true},
		{"failed_pr_creation done", AutofixStatus{State: "failed_pr_creation", Terminal: true}, true, true},
		{"creating_pr still waiting", AutofixStatus{State: "in_progress_creating_pr"}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, autofixPhaseDone(tt.st, tt.watchPR, earlier))
		})
	}
}

func TestFix(t *testing.T) {
	const (
		none       = `{"status":{"state":"none","terminal":false}}`
		cached     = `{"status":{"state":"cached","terminal":true}}`
		hasOldPR   = `{"status":{"state":"pending_review","terminal":true,"pullRequestUrl":"http://old","pullRequestState":"open","pullRequests":[{"url":"http://old","status":"open"}]}}`
		hasNewPR   = `{"status":{"state":"pending_review","terminal":true,"pullRequestUrl":"http://new","pullRequestState":"open","pullRequests":[{"url":"http://new","status":"open"},{"url":"http://old","status":"closed"}]}}`
		noPRClosed = `{"status":{"state":"failed_pr_creation","terminal":true,"pullRequestUrl":"http://old","pullRequestState":"closed","pullRequests":[{"url":"http://old","status":"closed"}]}}`
		abort      = `{"status":{"state":"failed_abort","terminal":true,"autofixVerdictExplanation":"needs a design change"}}`
		retry      = `{"status":{"state":"failed_retry","terminal":true}}`
		cancelled  = `{"status":{"state":"cancelled","terminal":true}}`
		iteration  = `{"status":{"state":"failed_iteration","terminal":true}}`
		openAfter  = `{"status":{"state":"failed_iteration","terminal":true,"pullRequests":[{"url":"http://new","status":"open"},{"url":"http://old","status":"closed"}]}}`
		closed     = `{"status":{"state":"pr_closed","terminal":true}}`
		unknown    = `{"status":{"state":"a_new_terminal_state","terminal":true}}`
	)

	const (
		sastFix    = "POST /sast/findings/f1/autofix/fix"
		sastStatus = "GET /sast/findings/f1/autofix/status"
		sastDiff   = "GET /sast/findings/f1/autofix/cache/diff"
	)

	tests := []struct {
		name     string
		findType string
		createPR bool
		statuses []string
		diffCode int
		want     error
		failure  error
		state    string
		routes   []string
		diff     bool
		pr       *PullRequestStatus
	}{
		{
			name: "sast reads the diff", findType: "sast", statuses: []string{cached},
			state: "cached", routes: []string{sastFix, sastStatus, sastDiff}, diff: true,
		},
		{
			name: "sca alias reports the pull request of this run", findType: "sca", createPR: true, statuses: []string{hasOldPR, hasNewPR, hasNewPR},
			state: "pending_review",
			routes: []string{
				"GET /sca/dependencies/findings/f1/autofix/status",
				"POST /sca/dependencies/findings/f1/autofix/fix",
				"GET /sca/dependencies/findings/f1/autofix/status",
				"GET /sca/dependencies/findings/f1/autofix/cache/diff",
				"GET /sca/dependencies/findings/f1/autofix/status",
			},
			diff: true,
			pr:   &PullRequestStatus{State: "open", URL: "http://new"},
		},
		{
			name: "cspm has no diff route", findType: "cspm", statuses: []string{cached},
			state: "cached", routes: []string{"POST /cspm/findings/f1/autofix/fix", "GET /cspm/findings/f1/autofix/status"},
		},
		{
			name: "an older pull request is not reported", findType: "sast", createPR: true, statuses: []string{hasOldPR, hasOldPR, hasOldPR},
			failure: ErrNoPullRequest, state: "pending_review",
			routes: []string{sastStatus, sastFix, sastStatus, sastDiff, sastStatus}, diff: true,
		},
		{
			name: "failed pull request creation does not report an older one", findType: "sast", createPR: true, statuses: []string{hasOldPR, cached, noPRClosed},
			failure: ErrAutofixFailed, state: "failed_pr_creation",
			routes: []string{sastStatus, sastFix, sastStatus, sastDiff, sastStatus}, diff: true,
		},
		{
			name: "failed_abort", findType: "sast", statuses: []string{abort},
			failure: ErrAutofixFailed, state: "failed_abort", routes: []string{sastFix, sastStatus},
		},
		{
			name: "failed_retry", findType: "sast", statuses: []string{retry},
			failure: ErrAutofixFailed, state: "failed_retry", routes: []string{sastFix, sastStatus},
		},
		{
			name: "cancelled", findType: "sast", statuses: []string{cancelled},
			failure: ErrAutofixFailed, state: "cancelled", routes: []string{sastFix, sastStatus},
		},
		{
			name: "failed_iteration", findType: "sast", statuses: []string{iteration},
			failure: ErrAutofixFailed, state: "failed_iteration", routes: []string{sastFix, sastStatus},
		},
		{
			name: "failed_iteration keeps its open pull request", findType: "sast", statuses: []string{openAfter},
			failure: ErrAutofixFailed, state: "failed_iteration", routes: []string{sastFix, sastStatus},
			pr: &PullRequestStatus{State: "open", URL: "http://new"},
		},
		{
			name: "pr_closed", findType: "sast", statuses: []string{closed},
			failure: ErrAutofixFailed, state: "pr_closed", routes: []string{sastFix, sastStatus},
		},
		{
			name: "an unknown terminal state is a failure", findType: "sast", statuses: []string{unknown},
			failure: ErrAutofixFailed, state: "a_new_terminal_state", routes: []string{sastFix, sastStatus},
		},
		{
			name: "failed run with create-pr stops after the fix phase", findType: "sast", createPR: true, statuses: []string{none, abort},
			failure: ErrAutofixFailed, state: "failed_abort", routes: []string{sastStatus, sastFix, sastStatus},
		},
		{
			name: "a failed diff read keeps the pull request", findType: "sast", createPR: true, statuses: []string{hasOldPR, hasNewPR, hasNewPR}, diffCode: 404,
			failure: ErrAutofixDiff, state: "pending_review",
			routes: []string{sastStatus, sastFix, sastStatus, sastDiff, sastStatus},
			pr:     &PullRequestStatus{State: "open", URL: "http://new"},
		},
		{name: "secrets has no autofix", findType: "secrets", want: ErrUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			polled := 0
			ft := &fakeTransport{respond: func(_ int, r request) (int, string) {
				if strings.HasSuffix(r.Path, "/diff") && tt.diffCode != 0 {
					return tt.diffCode, `{}`
				}
				if !strings.HasSuffix(r.Path, "/status") {
					return 200, `{}`
				}
				polled++
				return 200, tt.statuses[polled-1]
			}}

			got, err := Fix(context.Background(), clientFor(ft), tt.findType, "f1", FixOptions{WaitForPR: tt.createPR, Timeout: time.Minute})

			require.ErrorIs(t, err, tt.want)
			require.ErrorIs(t, got.Failure, tt.failure)
			var routes []string
			for _, r := range ft.requests {
				routes = append(routes, r.Method+" "+r.Path)
			}
			require.Equal(t, tt.routes, routes)
			require.Equal(t, tt.state, got.State)
			require.Equal(t, tt.diff, len(got.Diff) > 0)
			require.Equal(t, tt.pr, got.PullRequest)
		})
	}
}

func shortPollInterval(t *testing.T) {
	t.Helper()
	interval := autofixPollInterval
	t.Cleanup(func() { autofixPollInterval = interval })
	autofixPollInterval = 5 * time.Millisecond
}

func TestFixReportsStillRunningAtTheDeadline(t *testing.T) {
	shortPollInterval(t)

	tests := []struct {
		name     string
		status   string
		createPR bool
		state    string
	}{
		{name: "fix phase", status: `{"status":{"state":"in_progress_agent","terminal":false}}`, state: "in_progress_agent"},
		{name: "pull request phase", status: `{"status":{"state":"cached","terminal":true}}`, createPR: true, state: "cached"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{respond: func(_ int, r request) (int, string) {
				return 200, map[bool]string{true: tt.status, false: `{}`}[strings.HasSuffix(r.Path, "/status")]
			}}

			got, err := Fix(context.Background(), clientFor(ft), "sast", "f1", FixOptions{WaitForPR: tt.createPR, Timeout: 30 * time.Millisecond})

			require.ErrorIs(t, err, nil)
			require.ErrorIs(t, got.Failure, ErrAutofixStillRunning)
			require.ErrorContains(t, got.Failure, "nullify findings fix-status f1 --type sast")
			require.Equal(t, tt.state, got.State)
			require.Nil(t, got.PullRequest)
		})
	}
}

func TestFixBoundsHTTPReadsAndPolling(t *testing.T) {
	tests := []struct {
		name      string
		waitForPR bool
		stall     string
		want      error
		state     string
		check     string
	}{
		{
			name: "status request", stall: "status",
			want:  ErrAutofixStatusUnreadable,
			state: "in_progress_requested",
			check: "nullify findings fix-status f1 --type sast",
		},
		{
			name: "polling sleep", want: ErrAutofixStillRunning,
			state: "in_progress_agent",
			check: "nullify findings fix-status f1 --type sast",
		},
		{
			name: "diff request", stall: "diff",
			want: ErrAutofixDiff, state: "cached",
		},
		{
			name: "pull request polling", waitForPR: true,
			want: ErrAutofixStillRunning, state: "cached",
			check: "nullify findings fix-status f1 --type sast",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var statusReads atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/fix"):
					fmt.Fprint(w, `{"autoFixState":"in_progress_requested","runId":"r1"}`)
				case strings.HasSuffix(r.URL.Path, "/status"):
					statusReads.Add(1)
					if tt.stall == "status" {
						<-r.Context().Done()
						return
					}
					if tt.stall == "diff" || tt.waitForPR {
						fmt.Fprint(w, `{"status":{"state":"cached","terminal":true}}`)
					} else {
						fmt.Fprint(w, `{"status":{"state":"in_progress_agent","terminal":false}}`)
					}
				case strings.HasSuffix(r.URL.Path, "/diff"):
					if tt.stall == "diff" {
						<-r.Context().Done()
						return
					}
					fmt.Fprint(w, `{"diffs":[]}`)
				}
			}))
			t.Cleanup(server.Close)
			httpClient := server.Client()
			httpClient.Timeout = 2 * time.Second
			c := api.NewClient("acme.nullify.ai", "synthetic", nil,
				api.WithHTTPClient(httpClient))
			c.BaseURL = server.URL

			started := time.Now()
			got, err := Fix(context.Background(), c, "sast", "f1",
				FixOptions{WaitForPR: tt.waitForPR, Timeout: 100 * time.Millisecond})

			require.NoError(t, err)
			require.Less(t, time.Since(started), time.Second)
			require.Positive(t, statusReads.Load())
			require.ErrorIs(t, got.Failure, tt.want)
			require.Equal(t, tt.state, got.State)
			require.Equal(t, "r1", got.RunID)
			require.Equal(t, tt.check, got.CheckWith)
		})
	}
}

func TestFixPreservesCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			cancel()
			<-r.Context().Done()
			return
		}
		fmt.Fprint(w, `{"autoFixState":"in_progress_requested","runId":"r1"}`)
	}))
	t.Cleanup(server.Close)
	c := api.NewClient("acme.nullify.ai", "synthetic", nil,
		api.WithHTTPClient(server.Client()))
	c.BaseURL = server.URL

	got, err := Fix(ctx, c, "sast", "f1", FixOptions{Timeout: time.Minute})

	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, got.Failure, ErrAutofixStillRunning)
	require.Equal(t, "r1", got.RunID)
	require.Equal(t, "nullify findings fix-status f1 --type sast", got.CheckWith)
}

func TestFixStopsOnARescuedPullRequestStep(t *testing.T) {
	shortPollInterval(t)

	const creating = `{"status":{"state":"in_progress_creating_pr","terminal":false}}`
	const cached = `{"status":{"state":"cached","terminal":true}}`

	tests := []struct {
		name     string
		statuses []string
	}{
		{name: "the pull-request step started in the fix phase", statuses: []string{cached, creating, cached}},
		{name: "the pull-request step started after the fix phase", statuses: []string{cached, cached, creating, cached}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			polled := 0
			ft := &fakeTransport{respond: func(_ int, r request) (int, string) {
				if !strings.HasSuffix(r.Path, "/status") {
					return 200, `{}`
				}
				status := tt.statuses[min(polled, len(tt.statuses)-1)]
				polled++
				return 200, status
			}}

			got, err := Fix(context.Background(), clientFor(ft), "sast", "f1", FixOptions{WaitForPR: true, Timeout: time.Minute})

			require.ErrorIs(t, err, nil)
			require.ErrorIs(t, got.Failure, ErrNoPullRequest)
			require.NotErrorIs(t, got.Failure, ErrAutofixStillRunning)
			require.Equal(t, "cached", got.State)
			require.Nil(t, got.PullRequest)
		})
	}
}

func TestFixSaysWhenTheStatusCannotBeRead(t *testing.T) {
	shortPollInterval(t)

	const done = `{"status":{"state":"cached","terminal":true}}`

	tests := []struct {
		name     string
		createPR bool
		statuses []int
	}{
		{name: "fix phase", statuses: []int{500}},
		{name: "pull request phase", createPR: true, statuses: []int{200, 500}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			polled := 0
			ft := &fakeTransport{respond: func(_ int, r request) (int, string) {
				if !strings.HasSuffix(r.Path, "/status") {
					return 200, `{}`
				}
				code := tt.statuses[min(polled, len(tt.statuses)-1)]
				polled++
				return code, done
			}}

			got, err := Fix(context.Background(), clientFor(ft), "sast", "f1", FixOptions{WaitForPR: tt.createPR, Timeout: 30 * time.Millisecond})

			require.ErrorIs(t, err, nil)
			require.ErrorIs(t, got.Failure, ErrAutofixStatusUnreadable)
			require.NotErrorIs(t, got.Failure, ErrAutofixStillRunning)
			require.ErrorContains(t, got.Failure, "nullify findings fix-status f1 --type sast")
			require.Equal(t, "nullify findings fix-status f1 --type sast", got.CheckWith)
		})
	}
}

func TestFixKeepsTheDiffAsSent(t *testing.T) {
	const diff = `{"diffs":[],"addedLater":1}`
	ft := &fakeTransport{respond: func(_ int, r request) (int, string) {
		return 200, map[bool]string{true: diff, false: `{"status":{"state":"cached","terminal":true}}`}[strings.HasSuffix(r.Path, "/diff")]
	}}

	got, err := Fix(context.Background(), clientFor(ft), "sast", "f1", FixOptions{Timeout: time.Minute})

	require.ErrorIs(t, err, nil)
	require.ErrorIs(t, got.Failure, nil)
	require.Equal(t, diff, string(got.Diff))
}

func TestFixPollErrors(t *testing.T) {
	shortPollInterval(t)

	const done = `{"status":{"state":"cached","terminal":true}}`

	tests := []struct {
		name  string
		codes []int
		polls int
		state string
		want  bool
		check string
	}{
		{name: "a server error does not end the wait", codes: []int{503, 200}, polls: 2, state: "cached"},
		{name: "rate limiting does not end the wait", codes: []int{429, 200}, polls: 2, state: "cached"},
		{name: "no access ends the wait", codes: []int{403, 200}, polls: 1, state: "in_progress_requested", want: true, check: "nullify findings fix-status f1 --type sast"},
		{name: "not found ends the wait", codes: []int{404, 200}, polls: 1, state: "in_progress_requested", want: true, check: "nullify findings fix-status f1 --type sast"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			polls := 0
			ft := &fakeTransport{respond: func(_ int, r request) (int, string) {
				switch {
				case strings.HasSuffix(r.Path, "/status"):
					polls++
					return tt.codes[polls-1], done
				case strings.HasSuffix(r.Path, "/fix"):
					return 200, `{"autoFixState":"in_progress_requested","runId":"r1"}`
				}
				return 200, `{}`
			}}

			got, err := Fix(context.Background(), clientFor(ft), "sast", "f1", FixOptions{Timeout: time.Minute})

			var apiErr *apierror.APIError
			require.Equal(t, tt.want, errors.As(err, &apiErr))
			require.Equal(t, tt.polls, polls)
			require.Equal(t, tt.state, got.State)
			require.Equal(t, "r1", got.RunID)
			require.Equal(t, tt.check, got.CheckWith)
		})
	}
}

func TestStartFix(t *testing.T) {
	tests := []struct {
		name     string
		findType string
		want     error
		start    FixStart
		requests []request
	}{
		{
			name: "starts the run once and does not poll", findType: "sast",
			start:    FixStart{State: "in_progress_requested", RunID: "r1"},
			requests: []request{{"POST", "/sast/findings/f1/autofix/fix", `{}`}},
		},
		{name: "secrets has no autofix", findType: "secrets", want: ErrUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{respond: func(int, request) (int, string) {
				return 200, `{"autoFixState":"in_progress_requested","runId":"r1"}`
			}}

			got, err := StartFix(context.Background(), clientFor(ft), tt.findType, "f1")

			require.ErrorIs(t, err, tt.want)
			require.Equal(t, tt.start, got)
			require.Equal(t, tt.requests, ft.requests)
		})
	}
}

func TestFixRejectsAnInvalidTimeout(t *testing.T) {
	ft := &fakeTransport{}

	_, err := Fix(context.Background(), clientFor(ft), "sast", "f1", FixOptions{})

	require.ErrorIs(t, err, ErrInvalidTimeout)
	require.Empty(t, ft.requests)
}

func TestSensitiveDataVerbsUseTheirRoutes(t *testing.T) {
	const base = "/secrets/sensitivedata/findings/f1"
	falsePositive := Params{Reason: "test data", AllowlistType: "UserFalsePositive"}

	tests := []struct {
		name     string
		verb     string
		findType string
		params   Params
		request  request
	}{
		{name: "get", verb: "get", findType: "secrets_sensitive_data", request: request{"GET", base, ""}},
		{name: "triage", verb: "triage", findType: "secrets_sensitive_data", request: request{"GET", base + "/triage", ""}},
		{name: "allowlist", verb: "allowlist", findType: "secrets_sensitive_data", params: falsePositive, request: request{"POST", base + "/allowlist", `{"allowlistReason":"test data","allowlistType":"UserFalsePositive"}`}},
		{name: "unallowlist", verb: "unallowlist", findType: "secrets_sensitive_data", params: Params{Reason: "real"}, request: request{"POST", base + "/unallowlist", `{"unallowlistReason":"real","unallowlistType":"UserOther"}`}},
		{name: "credential unallowlist names a type", verb: "unallowlist", findType: "secrets", params: Params{Reason: "real"}, request: request{"POST", "/secrets/findings/f1/unallowlist", `{"unallowlistReason":"real","unallowlistType":"UserOther"}`}},
		{name: "create ticket", verb: "create-ticket", findType: "secrets_sensitive_data", request: request{"POST", base + "/ticket", `{}`}},
		{name: "delete ticket", verb: "delete-ticket", findType: "secrets_sensitive_data", request: request{"DELETE", base + "/ticket", ""}},
		{name: "row type of a sensitive-data finding", verb: "get", findType: "SecretsSensitiveData", request: request{"GET", base, ""}},
		{name: "row type of a credential", verb: "get", findType: "SecretsCredentials", request: request{"GET", "/secrets/findings/f1", ""}},
		{name: "secrets keeps the credential routes", verb: "get", findType: "secrets", request: request{"GET", "/secrets/findings/f1", ""}},
		{name: "row type of a cloud finding", verb: "get", findType: "Cloud", request: request{"GET", "/cspm/findings/f1", ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{}

			_, err := verbNamed(t, tt.verb).Run(context.Background(), clientFor(ft), tt.findType, "f1", tt.params)

			require.ErrorIs(t, err, nil)
			require.Equal(t, []request{tt.request}, ft.requests)
		})
	}
}

func TestAllowlistTypeWarning(t *testing.T) {
	falsePositive := Params{Reason: "r", AllowlistType: "UserFalsePositive"}

	tests := []struct {
		name     string
		verb     string
		findType string
		params   Params
		response string
		want     string
	}{
		{name: "bughunt warns", verb: "allowlist", findType: "bughunt", params: falsePositive, response: `{"success":true}`, want: `{"success":true,"warning":"` + AllowlistTypeWarning + `"}`},
		{name: "sca dependencies warns and keeps the response", verb: "allowlist", findType: "sca_dependencies", params: falsePositive, response: `{"a":1}`, want: `{"a":1,"warning":"` + AllowlistTypeWarning + `"}`},
		{name: "sensitive data warns", verb: "allowlist", findType: "secrets_sensitive_data", params: falsePositive, response: `{}`, want: `{"warning":"` + AllowlistTypeWarning + `"}`},
		{name: "cspm unallowlist says the reason is not recorded", verb: "unallowlist", findType: "cspm", params: Params{Reason: "r"}, response: `{}`, want: `{"warning":"` + UnallowlistReasonWarning + `"}`},
		{name: "pentest unallowlist records the reason", verb: "unallowlist", findType: "pentest", params: Params{Reason: "r"}, response: `{}`, want: `{}`},
		{name: "sca containers warns", verb: "allowlist", findType: "sca_containers", params: falsePositive, response: `{}`, want: `{"warning":"` + AllowlistTypeWarning + `"}`},
		{name: "a response that is not an object is kept", verb: "allowlist", findType: "sca", params: falsePositive, response: `done`, want: `{"response":"done","warning":"` + AllowlistTypeWarning + `"}`},
		{name: "cspm records the type", verb: "allowlist", findType: "cspm", params: falsePositive, response: `{}`, want: `{}`},
		{name: "secrets records the type", verb: "allowlist", findType: "secrets", params: falsePositive, response: `{}`, want: `{}`},
		{name: "unallowlist has no type", verb: "unallowlist", findType: "sca", params: Params{Reason: "r"}, response: `{}`, want: `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{respond: func(int, request) (int, string) { return 200, tt.response }}

			got, err := verbNamed(t, tt.verb).Run(context.Background(), clientFor(ft), tt.findType, "f1", tt.params)

			require.ErrorIs(t, err, nil)
			require.JSONEq(t, tt.want, string(got))
		})
	}
}

func TestVerbTypeValues(t *testing.T) {
	tests := []struct {
		verb string
		want []string
	}{
		{verb: "archive", want: []string{"Cloud", "cspm"}},
		{verb: "unmark-false-positive", want: []string{"Cloud", "Platform", "SupplyChain", "cspm", "scpm"}},
		{verb: "fix-diff", want: []string{"Code", "Dependencies", "dependencies", "sast", "sca", "sca_dependencies"}},
		{verb: "get", want: []string{
			"BugHunt", "Cloud", "Code", "Containers", "Dependencies", "Pentest", "Platform", "SecretsCredentials", "SecretsSensitiveData", "SupplyChain",
			"bughunt", "containers", "cspm", "dast_bughunt", "dast_pentest", "dependencies", "pentest", "sast", "sca", "sca_containers",
			"sca_dependencies", "scpm", "secrets", "secrets_credentials", "secrets_sensitive_data",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.verb, func(t *testing.T) {
			require.Equal(t, tt.want, verbNamed(t, tt.verb).TypeValues())
		})
	}
}
