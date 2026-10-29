package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

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
		return reply(200, `{"installations": [
		  {"name": "acme-web", "provider": {"id": "GitHub", "github": {}}, "nullifyBaseUrl": "https://api.acme.nullify.ai",
		   "queryParameters": {"githubOwnerId": "1001001"}, "provisioningStatus": "ready"},
		  {"name": "acme-payments", "provider": {"id": "GitHub", "github": {}}, "nullifyBaseUrl": "https://api.acme.nullify.ai",
		   "queryParameters": {"githubOwnerId": "2002002"}, "provisioningStatus": "ready"}]}`, nil)
	case r.URL.Host == "api.acme.nullify.ai":
		f.apiCalls = append(f.apiCalls, r.Header.Get("Authorization")+" "+r.URL.Query().Get("githubOwnerId"))
		if r.Header.Get("Authorization") != "Bearer "+f.live {
			return reply(401, `{"message":"Unauthorized"}`, nil)
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

	// The tenant stops accepting the token mid-session: the same process
	// refreshes at the router, never the tenant, and retries.
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
