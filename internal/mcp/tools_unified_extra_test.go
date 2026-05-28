package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nullify-platform/cli/internal/api"
)

// capturedReq records an outgoing request for assertions.
type capturedReq struct {
	method string
	path   string
	body   []byte
}

// fakeTransport intercepts every request, records it, and returns a canned
// response — letting us assert exactly what the tools send to the API without a
// real server.
type fakeTransport struct {
	mu       sync.Mutex
	requests []capturedReq
	respond  func(capturedReq) (int, string)
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var b []byte
	if req.Body != nil {
		b, _ = io.ReadAll(req.Body)
	}
	cr := capturedReq{method: req.Method, path: req.URL.Path, body: b}
	f.mu.Lock()
	f.requests = append(f.requests, cr)
	f.mu.Unlock()

	status, body := 200, "{}"
	if f.respond != nil {
		status, body = f.respond(cr)
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}, nil
}

func testClient(ft *fakeTransport) *api.Client {
	return api.NewClient("acme.nullify.ai", "tok", map[string]string{}, api.WithHTTPClient(&http.Client{Transport: ft}))
}

// findingsPage renders an /admin/findings page response with n findings.
func findingsPage(n, total int, hasMore bool) string {
	items := make([]string, n)
	for i := range items {
		items[i] = "{}"
	}
	return fmt.Sprintf(`{"findings":[%s],"total":%d,"hasMoreData":%t}`, strings.Join(items, ","), total, hasMore)
}

// reqQuery decodes the {"query": {...}} body the search sends.
func reqQuery(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var wrapper struct {
		Query map[string]any `json:"query"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		t.Fatalf("unmarshal body %q: %v", body, err)
	}
	return wrapper.Query
}

// Fix 3: pageSize must stay constant across pages — shrinking it would corrupt
// the page/offset math and skip or duplicate rows.
func TestSearchFindingsConstantPageSize(t *testing.T) {
	ft := &fakeTransport{respond: func(capturedReq) (int, string) {
		return 200, findingsPage(100, 1000, true)
	}}
	findings, total, err := searchFindings(context.Background(), testClient(ft), findingSearchOpts{limit: 250})
	if err != nil {
		t.Fatalf("searchFindings: %v", err)
	}
	if len(findings) != 250 {
		t.Errorf("got %d findings, want 250 (trimmed to limit)", len(findings))
	}
	if total != 1000 {
		t.Errorf("got total %d, want 1000", total)
	}
	if len(ft.requests) != 3 {
		t.Fatalf("got %d page requests, want 3", len(ft.requests))
	}
	for i, r := range ft.requests {
		q := reqQuery(t, r.body)
		if q["pageSize"] != float64(100) {
			t.Errorf("request %d pageSize = %v, want 100", i, q["pageSize"])
		}
		if q["page"] != float64(i+1) {
			t.Errorf("request %d page = %v, want %d", i, q["page"], i+1)
		}
	}
}

// Fix 2: repository and severity must reach the unified endpoint (the per-scanner
// GET listers silently drop both). Severity is uppercased for the API.
func TestSearchFindingsForwardsFilters(t *testing.T) {
	ft := &fakeTransport{respond: func(capturedReq) (int, string) {
		return 200, findingsPage(3, 3, false)
	}}
	_, _, err := searchFindings(context.Background(), testClient(ft), findingSearchOpts{
		apiTypes:   []string{"Code"},
		severity:   "critical",
		repository: "my-repo",
		status:     "open",
		limit:      20,
	})
	if err != nil {
		t.Fatalf("searchFindings: %v", err)
	}
	if len(ft.requests) != 1 {
		t.Fatalf("got %d requests, want 1", len(ft.requests))
	}
	r := ft.requests[0]
	if r.path != "/admin/findings" {
		t.Errorf("path = %q, want /admin/findings", r.path)
	}
	q := reqQuery(t, r.body)
	assertStringSlice(t, "repository", q["repository"], []string{"my-repo"})
	assertStringSlice(t, "severity", q["severity"], []string{"CRITICAL"})
	assertStringSlice(t, "type", q["type"], []string{"Code"})
	if q["isResolved"] != false {
		t.Errorf("status=open should set isResolved=false, got %v", q["isResolved"])
	}
}

func assertStringSlice(t *testing.T, name string, got any, want []string) {
	t.Helper()
	raw, ok := got.([]any)
	if !ok {
		t.Errorf("%s: not a slice: %v", name, got)
		return
	}
	if len(raw) != len(want) {
		t.Errorf("%s = %v, want %v", name, got, want)
		return
	}
	for i := range want {
		if raw[i] != want[i] {
			t.Errorf("%s[%d] = %v, want %q", name, i, raw[i], want[i])
		}
	}
}

// Fix 1: terminal detection must use the server's `terminal` flag, not substring
// matching. In particular "cached" (the normal SAST/SCA success state) is
// terminal for fix generation but must NOT end the PR-wait phase (no PR yet).
func TestAutofixPhaseDone(t *testing.T) {
	cases := []struct {
		name    string
		st      autofixStatus
		watchPR bool
		want    bool
	}{
		{"agent in progress", autofixStatus{State: "in_progress_agent", Terminal: false}, false, false},
		{"cached is terminal for fix", autofixStatus{State: "cached", Terminal: true}, false, true},
		{"pending_review terminal for fix", autofixStatus{State: "pending_review", Terminal: true}, false, true},
		{"failed_retry not terminal", autofixStatus{State: "failed_retry", Terminal: false}, false, false},

		{"cached without PR keeps waiting", autofixStatus{State: "cached", Terminal: true}, true, false},
		{"cached with PR url done", autofixStatus{State: "cached", Terminal: true, PullRequestURL: "http://pr"}, true, true},
		{"pending_review with url done", autofixStatus{State: "pending_review", Terminal: true, PullRequestURL: "http://pr"}, true, true},
		{"pr_merged terminal done", autofixStatus{State: "pr_merged", Terminal: true}, true, true},
		{"failed_pr_creation done", autofixStatus{State: "failed_pr_creation", Terminal: true}, true, true},
		{"creating_pr still waiting", autofixStatus{State: "in_progress_creating_pr", Terminal: false}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := autofixPhaseDone(tc.st, tc.watchPR); got != tc.want {
				t.Errorf("autofixPhaseDone(%+v, watchPR=%t) = %t, want %t", tc.st, tc.watchPR, got, tc.want)
			}
		})
	}
}

// Fix 6: bughunt's PATCH allowlist takes {allow, reason}; every other type's POST
// takes {allowlistReason, allowlistType}.
func TestAllowlistBody(t *testing.T) {
	std := allowlistBody(findingTypes["sast"], "looks fine", "UserFalsePositive")
	var stdBody map[string]any
	if err := json.Unmarshal(std, &stdBody); err != nil {
		t.Fatalf("unmarshal std body: %v", err)
	}
	if stdBody["allowlistReason"] != "looks fine" || stdBody["allowlistType"] != "UserFalsePositive" {
		t.Errorf("std allowlist body = %v, want {allowlistReason, allowlistType}", stdBody)
	}
	if _, ok := stdBody["allow"]; ok {
		t.Errorf("std allowlist body must not contain 'allow': %v", stdBody)
	}

	bug := allowlistBody(findingTypes["bughunt"], "looks fine", "UserFalsePositive")
	var bugBody map[string]any
	if err := json.Unmarshal(bug, &bugBody); err != nil {
		t.Fatalf("unmarshal bughunt body: %v", err)
	}
	if bugBody["allow"] != true || bugBody["reason"] != "looks fine" {
		t.Errorf("bughunt allowlist body = %v, want {allow:true, reason}", bugBody)
	}
	if _, ok := bugBody["allowlistType"]; ok {
		t.Errorf("bughunt allowlist body must not contain 'allowlistType': %v", bugBody)
	}
}

// listThreatInvestigations must paginate past the first page even though the
// server returns `numItems = len(page)` — the per-page count, not the total
// (manager/internal/endpoints/threatinvestigations_get.go). The previous break
// on `len(all) >= numItems` capped results at 50 regardless of limit.
func TestListThreatInvestigationsPaginatesPastPageOne(t *testing.T) {
	investigations := func(n int) string {
		items := make([]string, n)
		for i := range items {
			items[i] = `{}`
		}
		return strings.Join(items, ",")
	}
	page := 0
	ft := &fakeTransport{respond: func(capturedReq) (int, string) {
		page++
		// Two full pages of 50, then a short page of 20 (total 120 > limit 100).
		// numItems intentionally reports the per-page count to mirror the real
		// server behavior we used to be fooled by.
		switch page {
		case 1, 2:
			return 200, fmt.Sprintf(`{"threatInvestigations":[%s],"numItems":50}`, investigations(50))
		default:
			return 200, fmt.Sprintf(`{"threatInvestigations":[%s],"numItems":20}`, investigations(20))
		}
	}}

	all, err := listThreatInvestigations(context.Background(), testClient(ft), 100)
	if err != nil {
		t.Fatalf("listThreatInvestigations: %v", err)
	}
	if len(all) != 100 {
		t.Errorf("got %d investigations, want 100 (trimmed to limit)", len(all))
	}
	if len(ft.requests) != 2 {
		t.Errorf("got %d page requests, want 2 (limit hit after page 2)", len(ft.requests))
	}
}

// pollAutofix must unwrap the server's `{status: {...}}` envelope. The
// per-service endpoints (see hyperdrive's AutofixStatusOutput) wrap the
// state/terminal/pullRequestUrl fields under a named "status" key so the
// generator preserves typed-string enums. A flat unmarshal yields zero values,
// Terminal stays false, and the poll loop runs to the 5-minute deadline on
// every fix call.
func TestPollAutofixUnwrapsStatusEnvelope(t *testing.T) {
	ft := &fakeTransport{respond: func(capturedReq) (int, string) {
		return 200, `{"status":{"state":"cached","terminal":true},"version":"1"}`
	}}
	params := url.Values{}
	params.Set("findingId", "f1")

	st, err := pollAutofix(context.Background(), testClient(ft), findingTypes["sast"], params, false)
	if err != nil {
		t.Fatalf("pollAutofix: %v", err)
	}
	if !st.Terminal {
		t.Errorf("Terminal = false, want true (envelope not unwrapped)")
	}
	if st.State != "cached" {
		t.Errorf("State = %q, want %q", st.State, "cached")
	}
	if len(ft.requests) != 1 {
		t.Errorf("got %d polls, want 1 (terminal on first poll)", len(ft.requests))
	}
}

// On deadline, pollAutofix must return context.DeadlineExceeded so the tool
// can render a "still running" message instead of silently falling through to
// empty PR-URL output.
func TestPollAutofixSignalsDeadlineExceeded(t *testing.T) {
	t.Cleanup(func() {
		autofixPollDeadline = 5 * time.Minute
		autofixPollInterval = 3 * time.Second
	})
	autofixPollDeadline = 50 * time.Millisecond
	autofixPollInterval = 5 * time.Millisecond

	ft := &fakeTransport{respond: func(capturedReq) (int, string) {
		// Server never reports terminal — the polling loop runs to the deadline.
		return 200, `{"status":{"state":"in_progress_agent","terminal":false},"version":"1"}`
	}}
	params := url.Values{}
	params.Set("findingId", "f1")

	_, err := pollAutofix(context.Background(), testClient(ft), findingTypes["sast"], params, false)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if len(ft.requests) < 2 {
		t.Errorf("got %d polls, want >= 2 (loop ran at least one interval)", len(ft.requests))
	}
}

// searchFindings used to hard-pin pageSize=100, fetching ~100× the rows when
// composite tools requested a small limit. The clamp keeps pageSize within
// [20, 100] and constant across pages so the offset math stays valid.
func TestSearchFindingsClampsPageSize(t *testing.T) {
	cases := []struct {
		name     string
		limit    int
		wantPage int
	}{
		{"small limit clamps up to 20", 10, 20},
		{"medium limit uses limit", 40, 40},
		{"large limit clamps to 100", 250, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ft := &fakeTransport{respond: func(capturedReq) (int, string) {
				return 200, findingsPage(0, 0, false)
			}}
			_, _, err := searchFindings(context.Background(), testClient(ft), findingSearchOpts{limit: tc.limit})
			if err != nil {
				t.Fatalf("searchFindings: %v", err)
			}
			if len(ft.requests) == 0 {
				t.Fatalf("no requests")
			}
			q := reqQuery(t, ft.requests[0].body)
			if q["pageSize"] != float64(tc.wantPage) {
				t.Errorf("pageSize = %v, want %d", q["pageSize"], tc.wantPage)
			}
		})
	}
}
