package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
)

// countQuery is the part of a findings count request that the posture test reads.
type countQuery struct {
	Query struct {
		Type       []string `json:"type"`
		Severity   []string `json:"severity"`
		IsResolved *bool    `json:"isResolved"`
		Page       int      `json:"page"`
		PageSize   int      `json:"pageSize"`
		Repository []string `json:"repository"`
	} `json:"query"`
}

func TestPostureSummaryReportsTotalsByTypeAndSeverity(t *testing.T) {
	totals := map[string]int{"Code/CRITICAL": 2, "Code/HIGH": 5, "Code/LOW": 1, "Cloud/MEDIUM": 7, "BugHunt/HIGH": 3}
	ft := &fakeTransport{respond: func(r capturedReq) (int, string) {
		var q countQuery
		_ = json.Unmarshal(r.body, &q)
		if strings.Join(q.Query.Type, ",") == "Pentest" {
			return 500, `{"message":"boom"}`
		}
		total := totals[strings.Join(q.Query.Type, ",")+"/"+strings.Join(q.Query.Severity, ",")]
		return 200, `{"findings":[{}],"total":` + itoa(total) + `,"hasMoreData":true}`
	}}
	s := server.NewMCPServer("test", "1", server.WithToolCapabilities(true))
	registerCompositeTools(s, testClient(ft), Defaults{})

	result := callFindingTool(t, s, "get_security_posture_summary", nil)

	require.False(t, result.IsError, result.Content)
	var summary postureSummary
	require.NoError(t, json.Unmarshal([]byte(result.Content[0].(mcp.TextContent).Text), &summary))

	require.False(t, summary.Complete, "a failed count makes the summary incomplete")
	require.Equal(t, 18, summary.Total)
	require.Equal(t, map[string]int{"critical": 2, "high": 8, "medium": 7, "low": 1}, summary.BySeverity)

	byType := map[string]postureType{}
	for _, entry := range summary.Types {
		byType[entry.Type] = entry
	}
	require.Len(t, byType, len(scannerTypes))
	require.Equal(t, postureType{Type: "sast", Total: 8, BySeverity: map[string]int{"critical": 2, "high": 5, "medium": 0, "low": 1}}, byType["sast"])
	require.Equal(t, 3, byType["bughunt"].Total)
	require.Equal(t, 7, byType["cspm"].Total)
	require.NotEmpty(t, byType["pentest"].Error)
	require.Zero(t, byType["pentest"].Total)

	require.Len(t, ft.requests, len(scannerTypes)*len(postureSeverities))
	for _, r := range ft.requests {
		require.Equal(t, "POST", r.method)
		require.Equal(t, "/admin/findings", r.path, "no call lists findings")
		var q countQuery
		require.NoError(t, json.Unmarshal(r.body, &q))
		require.Equal(t, 1, q.Query.PageSize, "every call reads one finding")
		require.NotNil(t, q.Query.IsResolved)
		require.False(t, *q.Query.IsResolved, "only open findings are counted")
		require.Len(t, q.Query.Severity, 1)
	}
}

func TestPostureSummaryUsesTheDefaultRepository(t *testing.T) {
	ft := &fakeTransport{respond: func(capturedReq) (int, string) {
		return 200, `{"findings":[],"total":0,"hasMoreData":false}`
	}}
	s := server.NewMCPServer("test", "1", server.WithToolCapabilities(true))
	registerCompositeTools(s, testClient(ft), Defaults{Repository: "acme/widgets"})

	result := callFindingTool(t, s, "get_security_posture_summary", nil)

	require.False(t, result.IsError, result.Content)
	require.Len(t, result.Content, 2, "the result says which repository it counted")
	for _, r := range ft.requests {
		var q countQuery
		require.NoError(t, json.Unmarshal(r.body, &q))
		switch strings.Join(q.Query.Type, ",") {
		case "Cloud", "BugHunt":
			require.Nil(t, q.Query.Repository)
		default:
			require.Equal(t, []string{"acme/widgets", "widgets"}, q.Query.Repository)
		}
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
