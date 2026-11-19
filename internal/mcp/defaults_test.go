package mcp

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// repositoryFilterOf returns the repository filter of a findings or metrics
// request body, nil when it has none.
func repositoryFilterOf(t *testing.T, body string) []string {
	t.Helper()
	var parsed struct {
		Repository []string `json:"repository"`
		Query      struct {
			Repository []string `json:"repository"`
		} `json:"query"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &parsed), body)
	if parsed.Repository != nil {
		return parsed.Repository
	}
	return parsed.Query.Repository
}

func TestTheDefaultRepositoryFiltersFindingsSearches(t *testing.T) {
	bothNames := []string{"acme/widgets", "widgets"}
	tests := []struct {
		name string
		args map[string]any
		want []string
	}{
		{name: "a search of every type", args: map[string]any{}, want: bothNames},
		{name: "a search of a type with a repository", args: map[string]any{"type": "sast"}, want: bothNames},
		{name: "cloud findings have no repository", args: map[string]any{"type": "cspm"}},
		{name: "bug hunt findings have no repository", args: map[string]any{"type": "bughunt"}},
		{name: "an explicit repository wins", args: map[string]any{"repository": "acme/gadgets"}, want: []string{"acme/gadgets", "gadgets"}},
		{name: "a star searches every repository", args: map[string]any{"repository": "*"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, rec := newTestServer(t, orgsFor(map[string]string{"acme-web": "1001001"}, "acme-web"))

			res := callTool(t, s, "nullify_search_findings", tt.args)

			require.False(t, res.Result.IsError, res.Result.Content)
			bodies := rec.bodiesTo("/admin/findings")
			require.Len(t, bodies, 1)
			require.Equal(t, tt.want, repositoryFilterOf(t, bodies[0]))
		})
	}
}

func TestTheDefaultRepositoryIsReported(t *testing.T) {
	s, _ := newTestServer(t, orgsFor(map[string]string{"acme-web": "1001001"}, "acme-web"))

	res := callTool(t, s, "nullify_search_findings", map[string]any{"type": "sast"})

	var texts []string
	for _, c := range res.Result.Content {
		texts = append(texts, c.Text)
	}
	require.Contains(t, texts, repositoryNote(testRepository))
}

func TestNoDefaultRepositoryFiltersNothing(t *testing.T) {
	s, rec := newTestServerWith(t, orgsFor(map[string]string{"acme-web": "1001001"}, "acme-web"), ToolSetAll, Defaults{})

	require.False(t, callTool(t, s, "nullify_search_findings", map[string]any{"type": "sast"}).Result.IsError)
	require.False(t, callTool(t, s, "get_metrics_overview", nil).Result.IsError)

	require.Nil(t, repositoryFilterOf(t, rec.bodiesTo("/admin/findings")[0]))
	require.Nil(t, repositoryFilterOf(t, rec.bodiesTo("/admin/metrics/overview")[0]))
}

func TestTheDefaultRepositoryFiltersMetrics(t *testing.T) {
	tests := []struct {
		tool  string
		args  map[string]any
		paths []string
	}{
		{tool: "get_metrics_overview", paths: []string{"/admin/metrics/overview"}},
		{tool: "get_metrics_over_time", args: map[string]any{"period": "7d"}, paths: []string{"/admin/metrics/over-time"}},
		{tool: "get_security_trends", paths: []string{"/admin/metrics/overview", "/admin/metrics/over-time"}},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			s, rec := newTestServerWith(t, orgsFor(map[string]string{"acme-web": "1001001"}, "acme-web"), ToolSetAll, Defaults{Repository: testRepository})

			res := callTool(t, s, tt.tool, tt.args)

			require.False(t, res.Result.IsError, res.Result.Content)
			for _, path := range tt.paths {
				bodies := rec.bodiesTo(path)
				require.Len(t, bodies, 1, path)
				require.Equal(t, []string{"acme/widgets", "widgets"}, repositoryFilterOf(t, bodies[0]), path)
			}
		})
	}
}

func TestThePostureResourceUsesTheDefaultRepository(t *testing.T) {
	s, rec := newTestServer(t, orgsFor(map[string]string{"acme-web": "1001001"}, "acme-web"))

	res := call(t, s, "resources/read", map[string]any{"uri": "nullify://posture"})

	require.Nil(t, res.Error)
	bodies := rec.bodiesTo("/admin/metrics/overview")
	require.Len(t, bodies, 1)
	require.Equal(t, []string{"acme/widgets", "widgets"}, repositoryFilterOf(t, bodies[0]))
}

func TestCriticalPathUsesTheDefaultRepositoryForTypesWithOne(t *testing.T) {
	s, rec := newTestServer(t, orgsFor(map[string]string{"acme-web": "1001001"}, "acme-web"))

	res := callTool(t, s, "get_critical_path", nil)

	require.False(t, res.Result.IsError, res.Result.Content)
	bodies := rec.bodiesTo("/admin/findings")
	require.NotEmpty(t, bodies)
	for _, body := range bodies {
		var parsed struct {
			Query struct {
				Type []string `json:"type"`
			} `json:"query"`
		}
		require.NoError(t, json.Unmarshal([]byte(body), &parsed))
		if slices.Contains(parsed.Query.Type, "Cloud") || slices.Contains(parsed.Query.Type, "BugHunt") {
			require.Nil(t, repositoryFilterOf(t, body), body)
			continue
		}
		require.Equal(t, []string{"acme/widgets", "widgets"}, repositoryFilterOf(t, body), body)
	}
}
