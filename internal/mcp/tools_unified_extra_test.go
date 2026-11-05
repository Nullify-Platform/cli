package mcp

import (
	"context"
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
