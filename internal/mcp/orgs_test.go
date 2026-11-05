package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"github.com/nullify-platform/cli/internal/api"
	"github.com/stretchr/testify/require"
)

// scopeRecorder is a fake Nullify API that answers every call with an empty
// object and records each request's query.
type scopeRecorder struct {
	mu      sync.Mutex
	queries []url.Values
}

func (r *scopeRecorder) handler(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.queries = append(r.queries, req.URL.Query())
	r.mu.Unlock()
	_, _ = w.Write([]byte(`{}`))
}

func (r *scopeRecorder) seen() []url.Values {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]url.Values(nil), r.queries...)
}

// orgsFor fakes the CLI's resolution: org names map to owner ids, and an
// empty name falls back to def, or fails with the choices when def is "".
func orgsFor(byName map[string]string, def string) Orgs {
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	return Orgs{
		Resolve: func(_ context.Context, org string) (map[string]string, string, error) {
			if org == "" {
				org = def
			}
			if org == "" {
				return nil, "", fmt.Errorf("acme.nullify.ai serves %d organizations; choose one with --org: %s", len(byName), strings.Join(names, ", "))
			}
			id, ok := byName[org]
			if !ok {
				return nil, "", fmt.Errorf("org argument %q is not one of your organizations", org)
			}
			return map[string]string{"githubOwnerId": id}, org, nil
		},
		List: func(context.Context) (any, error) {
			return map[string]any{"organizations": names}, nil
		},
	}
}

func newTestServer(t *testing.T, orgs Orgs) (*server.MCPServer, *scopeRecorder) {
	t.Helper()
	rec := &scopeRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(rec.handler))
	t.Cleanup(srv.Close)

	c := api.NewClient("acme.nullify.ai", "tok", map[string]string{"repository": "widgets"},
		api.WithHTTPClient(&http.Client{Transport: ScopeTransport(srv.Client().Transport)}))
	c.BaseURL = srv.URL
	return NewServer(c, ToolSetDefault, orgs), rec
}

type rpcResult struct {
	Result struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Contents []struct {
			Text string `json:"text"`
		} `json:"contents"`
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Properties map[string]any `json:"properties"`
			} `json:"inputSchema"`
		} `json:"tools"`
	} `json:"result"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func call(t *testing.T, s *server.MCPServer, method string, params any) rpcResult {
	t.Helper()
	msg, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	require.NoError(t, err)
	out, err := json.Marshal(s.HandleMessage(context.Background(), msg))
	require.NoError(t, err)
	var res rpcResult
	require.NoError(t, json.Unmarshal(out, &res), string(out))
	return res
}

func callTool(t *testing.T, s *server.MCPServer, name string, args map[string]any) rpcResult {
	t.Helper()
	return call(t, s, "tools/call", map[string]any{"name": name, "arguments": args})
}

func TestServerStartsWithSeveralOrgsAndNoDefault(t *testing.T) {
	resolved := 0
	orgs := orgsFor(map[string]string{"acme-web": "1001001", "acme-payments": "2002002"}, "")
	resolve := orgs.Resolve
	orgs.Resolve = func(ctx context.Context, org string) (map[string]string, string, error) {
		resolved++
		return resolve(ctx, org)
	}

	s, rec := newTestServer(t, orgs)
	res := call(t, s, "tools/list", map[string]any{})
	require.Nil(t, res.Error)
	require.Zero(t, resolved, "listing tools must not need an org")
	require.Empty(t, rec.seen(), "starting must not call the API")
}

func TestEveryToolTakesAnOrgExceptListOrganizations(t *testing.T) {
	s, _ := newTestServer(t, orgsFor(map[string]string{"a": "1"}, "a"))
	res := call(t, s, "tools/list", map[string]any{})
	require.Nil(t, res.Error)
	require.NotEmpty(t, res.Result.Tools)

	sawList := false
	for _, tool := range res.Result.Tools {
		_, hasOrg := tool.InputSchema.Properties["org"]
		if tool.Name == "list_organizations" {
			sawList = true
			require.False(t, hasOrg, "list_organizations takes no org")
			continue
		}
		require.True(t, hasOrg, "%s has no org argument", tool.Name)
	}
	require.True(t, sawList)
}

func TestListOrganizationsTool(t *testing.T) {
	s, rec := newTestServer(t, orgsFor(map[string]string{"acme-web": "1001001"}, ""))
	res := callTool(t, s, "list_organizations", nil)
	require.False(t, res.Result.IsError, res.Result.Content)
	require.Contains(t, res.Result.Content[0].Text, "acme-web")
	require.Empty(t, rec.seen())
}

func TestOneOrgNeedsNoArgument(t *testing.T) {
	s, rec := newTestServer(t, orgsFor(map[string]string{"acme-payments": "2002002"}, "acme-payments"))
	res := callTool(t, s, "list_repositories", nil)
	require.False(t, res.Result.IsError, res.Result.Content)

	seen := rec.seen()
	require.Len(t, seen, 1)
	require.Equal(t, "2002002", seen[0].Get("githubOwnerId"))
	require.Equal(t, "widgets", seen[0].Get("repository"), "fixed scope survives")
}

func TestSeveralOrgsAndNoArgumentReturnsTheChoices(t *testing.T) {
	s, rec := newTestServer(t, orgsFor(map[string]string{"acme-web": "1001001", "acme-payments": "2002002"}, ""))
	res := callTool(t, s, "list_repositories", nil)

	require.True(t, res.Result.IsError)
	require.Contains(t, res.Result.Content[0].Text, "acme-web")
	require.Contains(t, res.Result.Content[0].Text, "acme-payments")
	require.Empty(t, rec.seen(), "no API call without an org")
}

func TestConcurrentCallsKeepTheirOwnOrg(t *testing.T) {
	s, rec := newTestServer(t, orgsFor(map[string]string{"acme-web": "1001001", "acme-payments": "2002002"}, ""))

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	for i := 0; i < n; i++ {
		for _, org := range []string{"acme-web", "acme-payments"} {
			wg.Add(1)
			go func(org string) {
				defer wg.Done()
				msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
					"params": map[string]any{"name": "list_repositories", "arguments": map[string]any{"org": org}}})
				out, _ := json.Marshal(s.HandleMessage(context.Background(), msg))
				if strings.Contains(string(out), `"isError":true`) {
					errs <- errors.New(string(out))
				}
			}(org)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	counts := map[string]int{}
	for _, q := range rec.seen() {
		require.Len(t, q["githubOwnerId"], 1, "one org per request: %v", q)
		counts[q.Get("githubOwnerId")]++
	}
	require.Equal(t, map[string]int{"1001001": n, "2002002": n}, counts)
}

func TestUnknownOrgArgumentIsAToolError(t *testing.T) {
	s, rec := newTestServer(t, orgsFor(map[string]string{"acme-payments": "2002002"}, "acme-payments"))
	res := callTool(t, s, "list_repositories", map[string]any{"org": "nope"})
	require.True(t, res.Result.IsError)
	require.Contains(t, res.Result.Content[0].Text, `"nope"`)
	require.Empty(t, rec.seen())
}

// An org the caller named must never turn into the default org: a numeric
// id is that id, and anything blank or of another type is refused.
func TestOrgArgumentIsTakenAsGivenOrRefused(t *testing.T) {
	orgs := orgsFor(map[string]string{"acme-web": "1001001", "1001001": "1001001", "acme-payments": "2002002"}, "acme-payments")

	s, rec := newTestServer(t, orgs)
	res := callTool(t, s, "list_repositories", map[string]any{"org": 1001001})
	require.False(t, res.Result.IsError, res.Result.Content)
	require.Equal(t, "1001001", rec.seen()[0].Get("githubOwnerId"), "a numeric id is that org, not the default")

	for _, bad := range []any{"", "   ", true, 1.5, map[string]any{"name": "acme-web"}, []any{"acme-web"}} {
		s, rec := newTestServer(t, orgs)
		res := callTool(t, s, "list_repositories", map[string]any{"org": bad})
		require.True(t, res.Result.IsError, "org %#v", bad)
		require.Contains(t, res.Result.Content[0].Text, "org argument")
		require.Empty(t, rec.seen(), "org %#v reached the API", bad)
	}
}

func TestResourceReadFollowsTheSameRule(t *testing.T) {
	ambiguous, rec := newTestServer(t, orgsFor(map[string]string{"acme-web": "1001001", "acme-payments": "2002002"}, ""))
	res := call(t, ambiguous, "resources/read", map[string]any{"uri": "nullify://repos"})
	require.NotNil(t, res.Error, "ambiguous org must fail the read")
	require.Contains(t, res.Error.Message, "acme-payments")
	require.Empty(t, rec.seen())

	single, rec := newTestServer(t, orgsFor(map[string]string{"acme-payments": "2002002"}, "acme-payments"))
	res = call(t, single, "resources/read", map[string]any{"uri": "nullify://repos"})
	require.Nil(t, res.Error)
	require.Len(t, rec.seen(), 1)
	require.Equal(t, "2002002", rec.seen()[0].Get("githubOwnerId"))
}

func TestScopeTransportLeavesUnscopedRequestsAlone(t *testing.T) {
	var got string
	tr := ScopeTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		got = r.URL.RawQuery
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	}))
	req, _ := http.NewRequest(http.MethodGet, "https://api.acme.nullify.ai/x?repository=w", nil)
	_, err := tr.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, "repository=w", got)

	req, _ = http.NewRequestWithContext(withScope(context.Background(), map[string]string{"githubOwnerId": "1"}),
		http.MethodGet, "https://api.acme.nullify.ai/x?repository=w&githubOwnerId=9", nil)
	_, err = tr.RoundTrip(req)
	require.NoError(t, err)
	q, _ := url.ParseQuery(got)
	require.Equal(t, []string{"1"}, q["githubOwnerId"], "the call's org replaces any default")
	require.Equal(t, "w", q.Get("repository"))
	require.Equal(t, "https://api.acme.nullify.ai/x?repository=w&githubOwnerId=9", req.URL.String(), "the caller's request is not mutated")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
