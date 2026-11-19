package mcp

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
)

func TestListApplicationsSendsTheLimit(t *testing.T) {
	ft := &fakeTransport{}
	s := server.NewMCPServer("test", "1", server.WithToolCapabilities(true))
	registerContextTools(s, testClient(ft))

	result := callFindingTool(t, s, "list_applications", map[string]any{"limit": 5})

	require.False(t, result.IsError, result.Content)
	require.Len(t, ft.requests, 1)
	require.Equal(t, "/context/applications", ft.requests[0].path)
	require.Equal(t, url.Values{"limit": {"5"}}, ft.queries[0])
}

func TestRecentFindingsAreTheNewest(t *testing.T) {
	ft := &fakeTransport{}
	s := server.NewMCPServer("test", "1", server.WithResourceCapabilities(false, false))
	registerResources(s, testClient(ft), Defaults{})

	msg, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": map[string]any{"uri": "nullify://recent-findings"}})
	require.NoError(t, err)
	out, err := json.Marshal(s.HandleMessage(context.Background(), msg))
	require.NoError(t, err)
	require.NotContains(t, string(out), `"error"`, string(out))

	paths := make([]string, 0, len(ft.requests))
	for i, r := range ft.requests {
		paths = append(paths, r.path)
		require.Equal(t, "time", ft.queries[i].Get("sortBy"), r.path)
		require.Equal(t, "desc", ft.queries[i].Get("sort"), r.path)
		require.Equal(t, "5", ft.queries[i].Get("limit"), r.path)
	}
	require.Equal(t, []string{"/sast/findings", "/sca/dependencies/findings", "/secrets/credentials/findings"}, paths)
}

func TestInvestigateRepoPromptSearchesOnlyTypesWithARepository(t *testing.T) {
	s := server.NewMCPServer("test", "1", server.WithPromptCapabilities(true))
	registerPrompts(s)

	msg, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "prompts/get",
		"params": map[string]any{"name": "investigate-repo", "arguments": map[string]string{"repository": "acme/widgets"}}})
	require.NoError(t, err)
	out, err := json.Marshal(s.HandleMessage(context.Background(), msg))
	require.NoError(t, err)

	var res struct {
		Result struct {
			Messages []struct {
				Content struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"messages"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(out, &res))
	require.Len(t, res.Result.Messages, 1)
	text := res.Result.Messages[0].Content.Text

	_, rest, found := strings.Cut(text, "(")
	require.True(t, found, text)
	list, _, found := strings.Cut(rest, ")")
	require.True(t, found, text)
	require.Equal(t, "sast, sca_dependencies, sca_containers, secrets, pentest, scpm", list)
	require.Contains(t, text, "cspm")
	require.Contains(t, text, "bughunt")
	require.Contains(t, text, "have no repository")
}

func TestResourcesDoNotAdvertiseSubscriptions(t *testing.T) {
	s := NewServer(nil, ToolSetMinimal, Orgs{}, Defaults{})

	msg, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"},
	}})
	require.NoError(t, err)
	out, err := json.Marshal(s.HandleMessage(context.Background(), msg))
	require.NoError(t, err)
	var init struct {
		Result struct {
			Capabilities struct {
				Resources *struct {
					Subscribe bool `json:"subscribe"`
				} `json:"resources"`
			} `json:"capabilities"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(out, &init))
	require.NotNil(t, init.Result.Capabilities.Resources, "resources are still advertised")
	require.False(t, init.Result.Capabilities.Resources.Subscribe, "the server never sends resource updates")
}
