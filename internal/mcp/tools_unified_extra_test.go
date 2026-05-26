package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

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
