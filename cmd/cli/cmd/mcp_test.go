package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/logger"
	"github.com/nullify-platform/cli/internal/mcp"
	"github.com/stretchr/testify/require"
)

// fakeNullify stands in for the router and the acme tenant at the transport
// level, so the real auth, refresh and client code run unchanged.
type fakeNullify struct {
	mu        sync.Mutex
	live      string // the access token the tenant accepts
	refreshes []string
	apiCalls  []string
	lists     int
	notHosted string // an owner id the tenant refuses as not hosted there
}

func (f *fakeNullify) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(status int, body string, header http.Header) (*http.Response, error) {
		if header == nil {
			header = http.Header{}
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	}

	switch {
	case r.URL.Host == "api.nullify.ai" && r.URL.Path == "/auth/refresh_token":
		f.refreshes = append(f.refreshes, r.URL.Host)
		f.live = "refreshed-token"
		h := http.Header{}
		h.Add("Set-Cookie", "access_token=refreshed-token; Max-Age=3600; Path=/; Secure; HttpOnly")
		return reply(200, `{"expiresIn":3600}`, h)
	case r.URL.Host == "api.nullify.ai" && r.URL.Path == "/admin/installations":
		f.lists++
		if r.Header.Get("Authorization") != "Bearer "+f.live {
			return reply(401, `{"message":"Unauthorized"}`, nil)
		}
		return reply(200, `{"installations": [
		  {"name": "acme-web", "provider": {"id": "GitHub", "github": {}}, "nullifyBaseUrl": "https://api.acme.nullify.ai",
		   "queryParameters": {"githubOwnerId": "1001001"}, "provisioningStatus": "ready"},
		  {"name": "acme-payments", "provider": {"id": "GitHub", "github": {}}, "nullifyBaseUrl": "https://api.acme.nullify.ai",
		   "queryParameters": {"githubOwnerId": "2002002"}, "provisioningStatus": "ready"},
		  {"name": "beta-org", "provider": {"id": "GitHub", "github": {}}, "nullifyBaseUrl": "https://api.beta.nullify.ai",
		   "queryParameters": {"githubOwnerId": "3003003"}, "provisioningStatus": "ready"}]}`, nil)
	case r.URL.Host == "api.acme.nullify.ai":
		f.apiCalls = append(f.apiCalls, r.Header.Get("Authorization")+" "+r.URL.Query().Get("githubOwnerId"))
		if r.Header.Get("Authorization") != "Bearer "+f.live {
			return reply(401, `{"message":"Unauthorized"}`, nil)
		}
		if id := r.URL.Query().Get("githubOwnerId"); id != "" && id == f.notHosted {
			return reply(403, `{"message":"Organization GitHub `+id+` is not hosted on this instance."}`, nil)
		}
		return reply(200, `{}`, nil)
	}
	return reply(404, "", nil)
}

func TestMCPServeOnARouterLogin(t *testing.T) {
	loginEnv(t)
	fake := &fakeNullify{live: "router-token"}
	old := http.DefaultTransport
	http.DefaultTransport = fake
	t.Cleanup(func() { http.DefaultTransport = old })

	ctx, err := logger.ConfigureDevelopmentLogger(context.Background(), "error")
	require.NoError(t, err)

	apiClient, toolSet, orgs, err := mcpServeConfig(ctx, "widgets", "default")
	require.NoError(t, err, "serve starts with two orgs and no org chosen")
	s := mcp.NewServer(apiClient, toolSet, orgs)

	call := func(args map[string]any) string {
		msg, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": "list_repositories", "arguments": args}})
		require.NoError(t, err)
		out, err := json.Marshal(s.HandleMessage(ctx, msg))
		require.NoError(t, err)
		return string(out)
	}

	out := call(nil)
	require.Contains(t, out, `"isError":true`, "two orgs and no org argument")
	require.Contains(t, out, "acme-payments")
	require.Contains(t, out, "pass the org argument")

	out = call(map[string]any{"org": "acme-payments"})
	require.NotContains(t, out, `"isError":true`, out)

	// The token stops being accepted mid-session, before its stored expiry:
	// the API call refreshes once, at the router, never the tenant, and
	// retries; the org list is still cached.
	fake.mu.Lock()
	fake.live = "only-a-refresh-gets-this"
	fake.mu.Unlock()
	out = call(map[string]any{"org": "acme-web"})
	require.NotContains(t, out, `"isError":true`, out)

	fake.mu.Lock()
	defer fake.mu.Unlock()
	require.Equal(t, []string{"api.nullify.ai"}, fake.refreshes)
	require.Equal(t, []string{
		"Bearer router-token 2002002",
		"Bearer router-token 1001001",
		"Bearer refreshed-token 1001001",
	}, fake.apiCalls)

	creds, err := auth.LoadCredentials()
	require.NoError(t, err)
	require.Equal(t, "refreshed-token", creds["nullify.ai"].AccessToken, "the refreshed router login is saved")
}

// serve --org is the default for calls that name no org; a call's own org
// argument still wins.
func TestMCPServeOrgFlagIsTheDefault(t *testing.T) {
	loginEnv(t)
	fake := &fakeNullify{live: "router-token"}
	old := http.DefaultTransport
	http.DefaultTransport = fake
	t.Cleanup(func() { http.DefaultTransport = old })
	orgFlag = "acme-payments"

	ctx, err := logger.ConfigureDevelopmentLogger(context.Background(), "error")
	require.NoError(t, err)
	apiClient, toolSet, orgs, err := mcpServeConfig(ctx, "", "default")
	require.NoError(t, err)
	s := mcp.NewServer(apiClient, toolSet, orgs)

	for _, args := range []map[string]any{nil, {"org": "acme-web"}} {
		msg, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": "list_repositories", "arguments": args}})
		require.NoError(t, err)
		out, err := json.Marshal(s.HandleMessage(ctx, msg))
		require.NoError(t, err)
		require.NotContains(t, string(out), `"isError":true`, string(out))
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	require.Equal(t, []string{"Bearer router-token 2002002", "Bearer router-token 1001001"}, fake.apiCalls)
}

func mcpCall(t *testing.T, ctx context.Context, s *server.MCPServer, args map[string]any) string {
	t.Helper()
	msg, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "list_repositories", "arguments": args}})
	require.NoError(t, err)
	out, err := json.Marshal(s.HandleMessage(ctx, msg))
	require.NoError(t, err)
	return string(out)
}

func startMCP(t *testing.T, fake *fakeNullify) (context.Context, *server.MCPServer) {
	t.Helper()
	old := http.DefaultTransport
	http.DefaultTransport = fake
	t.Cleanup(func() { http.DefaultTransport = old })
	ctx, err := logger.ConfigureDevelopmentLogger(context.Background(), "error")
	require.NoError(t, err)
	apiClient, toolSet, orgs, err := mcpServeConfig(ctx, "", "default")
	require.NoError(t, err)
	return ctx, mcp.NewServer(apiClient, toolSet, orgs)
}

// The default a server runs calls as is settled from what it started with:
// 'nullify org use' in a terminal while it runs does not move it, and every
// result names the org it ran as.
func TestMCPDefaultOrgIsFixedAtStart(t *testing.T) {
	loginEnv(t)
	require.NoError(t, auth.SelectOrg(testOrgA))
	fake := &fakeNullify{live: "router-token"}
	ctx, s := startMCP(t, fake)

	out := mcpCall(t, ctx, s, nil)
	require.Contains(t, out, "Organization: acme-web")

	require.NoError(t, auth.SelectOrg(testOrgB))
	out = mcpCall(t, ctx, s, nil)
	require.Contains(t, out, "Organization: acme-web", "a terminal org use moved a running server")
	out = mcpCall(t, ctx, s, map[string]any{"org": "acme-payments"})
	require.Contains(t, out, "Organization: acme-payments")

	fake.mu.Lock()
	defer fake.mu.Unlock()
	require.Equal(t, []string{"Bearer router-token 1001001", "Bearer router-token 1001001", "Bearer router-token 2002002"}, fake.apiCalls)
}

// Twenty calls across both orgs at once, all rejected for an expired token:
// each keeps its own org, and the router refreshes once.
func TestMCPConcurrentCallsAcrossOrgsRefreshOnce(t *testing.T) {
	loginEnv(t)
	fake := &fakeNullify{live: "router-token"}
	ctx, s := startMCP(t, fake)
	require.NotContains(t, mcpCall(t, ctx, s, map[string]any{"org": "acme-web"}), `"isError":true`)

	fake.mu.Lock()
	fake.live = "only-a-refresh-gets-this"
	fake.apiCalls = nil
	fake.mu.Unlock()

	var wg sync.WaitGroup
	outs := make([]string, 20)
	for i := range outs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			org := []string{"acme-web", "acme-payments"}[i%2]
			outs[i] = mcpCall(t, ctx, s, map[string]any{"org": org})
		}()
	}
	wg.Wait()

	for i, out := range outs {
		org := []string{"acme-web", "acme-payments"}[i%2]
		require.NotContains(t, out, `"isError":true`, out)
		require.Contains(t, out, "Organization: "+org)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	require.Equal(t, []string{"api.nullify.ai"}, fake.refreshes)
	for _, call := range fake.apiCalls {
		require.True(t, strings.HasSuffix(call, " 1001001") || strings.HasSuffix(call, " 2002002"), call)
	}
}

// A call the tenant refuses because the org is not hosted there is returned
// as is, not replayed, and the server's org list is fetched again so the
// next call sees where the org went. An org on another tenant is named with
// its host, and a name that is no org is refused.
func TestMCPNotHostedRefreshesTheOrgList(t *testing.T) {
	loginEnv(t)
	fake := &fakeNullify{live: "router-token", notHosted: "2002002"}
	ctx, s := startMCP(t, fake)

	require.NotContains(t, mcpCall(t, ctx, s, map[string]any{"org": "acme-web"}), `"isError":true`)
	require.NotContains(t, mcpCall(t, ctx, s, map[string]any{"org": "acme-web"}), `"isError":true`)
	fake.mu.Lock()
	lists := fake.lists
	fake.mu.Unlock()

	out := mcpCall(t, ctx, s, map[string]any{"org": "acme-payments"})
	require.Contains(t, out, "not hosted on this instance")
	fake.mu.Lock()
	calls := 0
	for _, c := range fake.apiCalls {
		if strings.HasSuffix(c, " 2002002") {
			calls++
		}
	}
	fake.mu.Unlock()
	require.Equal(t, 1, calls, "the refused call was replayed")

	require.NotContains(t, mcpCall(t, ctx, s, map[string]any{"org": "acme-web"}), `"isError":true`)
	fake.mu.Lock()
	require.Equal(t, lists+1, fake.lists, "the org list was not fetched again after the refusal")
	fake.mu.Unlock()

	out = mcpCall(t, ctx, s, map[string]any{"org": "beta-org"})
	require.Contains(t, out, `"isError":true`)
	require.Contains(t, out, "api.beta.nullify.ai")

	out = mcpCall(t, ctx, s, map[string]any{"org": "acme-wbe"})
	require.Contains(t, out, `"isError":true`)
	require.Contains(t, out, "not one of your organizations")
}
