package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
)

func callTool(t *testing.T, s *server.MCPServer, name string, args map[string]any) mcp.CallToolResult {
	t.Helper()
	message, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": name, "arguments": args},
	})
	require.NoError(t, err)

	raw, err := json.Marshal(s.HandleMessage(context.Background(), message))
	require.NoError(t, err)

	var response struct {
		Result json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &response))
	result, err := mcp.ParseCallToolResult(&response.Result)
	require.NoError(t, err)
	return *result
}

func TestFindingTools(t *testing.T) {
	falsePositive := map[string]any{"type": "cspm", "id": "f1", "allowlist_type": "UserFalsePositive", "reason": "public by design"}

	tests := []struct {
		name     string
		tool     string
		args     map[string]any
		isError  bool
		requests []capturedReq
	}{
		{
			name: "allowlist cspm", tool: "nullify_allowlist_finding", args: falsePositive,
			requests: []capturedReq{{"POST", "/cspm/findings/f1/allowlist", []byte(`{"allowlistReason":"public by design","allowlistType":"UserFalsePositive"}`)}},
		},
		{
			name: "unallowlist cspm", tool: "nullify_unallowlist_finding", args: map[string]any{"type": "cspm", "id": "f1", "reason": "reopen"},
			requests: []capturedReq{{"POST", "/cspm/findings/f1/unallowlist", []byte(`{"unallowlistReason":"reopen"}`)}},
		},
		{
			name: "allowlist bughunt keeps the PATCH body", tool: "nullify_allowlist_finding", args: map[string]any{"type": "bughunt", "id": "f1", "allowlist_type": "UserOther", "reason": "r"},
			requests: []capturedReq{{"PATCH", "/dast/bughunt/findings/f1/allowlist", []byte(`{"allow":true,"reason":"r"}`)}},
		},
		{
			name: "unallowlist bughunt", tool: "nullify_unallowlist_finding", args: map[string]any{"type": "bughunt", "id": "f1", "reason": "r"},
			requests: []capturedReq{{"PATCH", "/dast/bughunt/findings/f1/allowlist", []byte(`{"allow":false,"reason":"r"}`)}},
		},
		{
			name: "archive cspm", tool: "nullify_archive_finding", args: map[string]any{"type": "cspm", "id": "f1"},
			requests: []capturedReq{{"POST", "/cspm/findings/f1/archive", []byte(`{}`)}},
		},
		{
			name: "mark false positive", tool: "nullify_mark_false_positive", args: map[string]any{"type": "cspm", "id": "f1", "reason": "r"},
			requests: []capturedReq{{"POST", "/cspm/findings/f1/mark-false-positive", []byte(`{"falsePositiveReason":"r"}`)}},
		},
		{
			name: "triage cspm", tool: "nullify_get_finding_triage", args: map[string]any{"type": "cspm", "id": "f1"},
			requests: []capturedReq{{"GET", "/cspm/findings/f1/triage", nil}},
		},
		{
			name: "delete ticket", tool: "nullify_delete_ticket", args: map[string]any{"type": "scpm", "id": "f1"},
			requests: []capturedReq{{"DELETE", "/scpm/findings/f1/ticket", nil}},
		},
		{
			name: "submit feedback", tool: "nullify_submit_finding_feedback", args: map[string]any{"id": "f1", "verdict": "wrong", "comment": "not reachable"},
			requests: []capturedReq{{"POST", "/findings/f1/feedback", []byte(`{"commentText":"not reachable","verdict":"wrong"}`)}},
		},
		{
			name: "get feedback", tool: "nullify_get_finding_feedback", args: map[string]any{"id": "f1"},
			requests: []capturedReq{{"GET", "/findings/f1/feedback", nil}},
		},
		{name: "allowlist without a type sends nothing", tool: "nullify_allowlist_finding", args: map[string]any{"type": "cspm", "id": "f1", "reason": "r"}, isError: true},
		{name: "allowlist without a reason sends nothing", tool: "nullify_allowlist_finding", args: map[string]any{"type": "cspm", "id": "f1", "allowlist_type": "UserFixed"}, isError: true},
		{name: "archive on sast sends nothing", tool: "nullify_archive_finding", args: map[string]any{"type": "sast", "id": "f1"}, isError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{}
			s := server.NewMCPServer("test", "1", server.WithToolCapabilities(true))
			registerUnifiedTools(s, testClient(ft))
			registerOptInFindingTools(s, testClient(ft))

			result := callTool(t, s, tt.tool, tt.args)

			require.Equal(t, tt.isError, result.IsError)
			require.Equal(t, tt.requests, ft.requests)
		})
	}
}

func TestSearchToolReportsCompleteness(t *testing.T) {
	tests := []struct {
		name string
		args map[string]any
		body string
		want string
		sent string
	}{
		{
			name: "scpm uses its API type and an empty result is reported as complete",
			args: map[string]any{"type": "scpm"},
			body: `{"findings":[],"total":0,"hasMoreData":false,"page":1}`,
			want: `{"findings":[],"total":0,"returned":0,"truncated":false}`,
			sent: `"type":["SupplyChain"]`,
		},
		{
			name: "a cut-off result is reported as truncated",
			args: map[string]any{"type": "cspm", "limit": 1},
			body: `{"findings":[{}],"total":9,"hasMoreData":true,"page":1}`,
			want: `{"total":9,"returned":1,"truncated":true}`,
			sent: `"type":["Cloud"]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{respond: func(capturedReq) (int, string) { return 200, tt.body }}
			s := server.NewMCPServer("test", "1", server.WithToolCapabilities(true))
			registerUnifiedTools(s, testClient(ft))

			result := callTool(t, s, "nullify_search_findings", tt.args)

			require.False(t, result.IsError)
			text, ok := result.Content[0].(mcp.TextContent)
			require.True(t, ok)
			require.JSONEqf(t, withoutFindings(t, tt.want), withoutFindings(t, text.Text), "tool result %s", text.Text)
			require.Contains(t, string(ft.requests[0].body), tt.sent)
		})
	}
}

func withoutFindings(t *testing.T, doc string) string {
	t.Helper()
	var fields map[string]any
	require.NoError(t, json.Unmarshal([]byte(doc), &fields))
	delete(fields, "findings")
	out, err := json.Marshal(fields)
	require.NoError(t, err)
	return string(out)
}

func TestFixToolStartsTheRunAndReturns(t *testing.T) {
	ft := &fakeTransport{respond: func(capturedReq) (int, string) {
		return 200, `{"autoFixState":"in_progress_requested","runId":"r1"}`
	}}
	s := server.NewMCPServer("test", "1", server.WithToolCapabilities(true))
	registerUnifiedTools(s, testClient(ft))

	result := callTool(t, s, "nullify_fix_finding", map[string]any{"type": "sast", "id": "f1"})

	require.False(t, result.IsError)
	require.JSONEq(t, `{"state":"in_progress_requested","run_id":"r1","check_with":"nullify_get_fix_status"}`, result.Content[0].(mcp.TextContent).Text)
	require.Equal(t, []capturedReq{{"POST", "/sast/findings/f1/autofix/fix", []byte(`{}`)}}, ft.requests)
}

func TestFindingsForRepo(t *testing.T) {
	tests := []struct {
		name  string
		want  []string
		never string
	}{
		{name: "cloud findings have no repository", want: []string{"--- cspm ---\nNot listed: these findings have no repository."}, never: `"Cloud"`},
		{name: "bug hunt findings have no repository", want: []string{"--- bughunt ---\nNot listed: these findings have no repository."}, never: `"BugHunt"`},
		{name: "a section reports truncation", want: []string{`"truncated": true`, `"total": 9`, `"returned": 1`}, never: `"Cloud"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{respond: func(capturedReq) (int, string) {
				return 200, `{"findings":[{}],"total":9,"hasMoreData":true}`
			}}
			s := server.NewMCPServer("test", "1", server.WithToolCapabilities(true))
			registerCompositeTools(s, testClient(ft))

			result := callTool(t, s, "get_findings_for_repo", map[string]any{"repository": "acme/app", "limit": 1})

			text := result.Content[0].(mcp.TextContent).Text
			for _, want := range tt.want {
				require.Contains(t, text, want)
			}
			for _, r := range ft.requests {
				require.NotContains(t, string(r.body), tt.never)
			}
		})
	}
}

func TestValidToolSets(t *testing.T) {
	require.ElementsMatch(t, []string{"default", "all", "minimal", "findings", "admin", "findings-write"}, ValidToolSets())
}
