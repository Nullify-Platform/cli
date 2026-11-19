package mcp

import (
	"net/url"
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
)

func TestListRepositoriesPages(t *testing.T) {
	tests := []struct {
		name  string
		args  map[string]any
		query url.Values
	}{
		{name: "the first page", args: map[string]any{"limit": 10}, query: url.Values{"limit": {"10"}}},
		{name: "a later page", args: map[string]any{"limit": 10, "next_token": "t1"}, query: url.Values{"limit": {"10"}, "nextToken": {"t1"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{}
			s := server.NewMCPServer("test", "1", server.WithToolCapabilities(true))
			registerContextTools(s, testClient(ft))

			result := callFindingTool(t, s, "list_repositories", tt.args)

			require.False(t, result.IsError, result.Content)
			require.Len(t, ft.requests, 1)
			require.Equal(t, "/context/repositories", ft.requests[0].path)
			require.Equal(t, tt.query, ft.queries[0])
		})
	}
}
