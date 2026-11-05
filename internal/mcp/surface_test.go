package mcp

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const toolSnapshot = "../../spec/mcp-tools.tsv"

func TestToolSurfaceMatchesSnapshot(t *testing.T) {
	content, err := os.ReadFile(toolSnapshot)
	require.ErrorIs(t, err, nil)

	require.Equal(t, string(content), FormatToolSurface(ToolSurface()), "run make command-surface")
}

func TestCheckToolSurface(t *testing.T) {
	readOnly := ToolEntry{Name: "a", Annotation: "read-only", Sets: []string{"all", "default"}}
	destructive := ToolEntry{Name: "a", Annotation: "destructive", Sets: []string{"all", "default"}}
	optIn := ToolEntry{Name: "a", Annotation: "read-only", Sets: []string{"all"}}
	evidence := map[string]string{"a": "evidence"}

	tests := []struct {
		name      string
		base      []ToolEntry
		live      []ToolEntry
		decisions ToolDecisions
		want      error
	}{
		{name: "kept", base: []ToolEntry{readOnly}, live: []ToolEntry{readOnly}},
		{name: "added", live: []ToolEntry{readOnly}},
		{name: "gone", base: []ToolEntry{readOnly}, want: ErrToolDisappeared},
		{name: "gone with a decision", base: []ToolEntry{readOnly}, decisions: ToolDecisions{Removed: evidence}},
		{name: "annotation changed", base: []ToolEntry{destructive}, live: []ToolEntry{readOnly}, want: ErrToolChanged},
		{name: "tool sets changed", base: []ToolEntry{optIn}, live: []ToolEntry{readOnly}, want: ErrToolChanged},
		{name: "changed with a decision", base: []ToolEntry{destructive}, live: []ToolEntry{readOnly}, decisions: ToolDecisions{Changed: evidence}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorIs(t, CheckToolSurface(tt.base, tt.live, tt.decisions), tt.want)
		})
	}
}

func TestParseToolSurface(t *testing.T) {
	entries := []ToolEntry{{Name: "a", Annotation: "read-only", Sets: []string{"all", "default"}}, {Name: "b", Annotation: "destructive", Sets: []string{"all"}}}

	got, err := ParseToolSurface(FormatToolSurface(entries))
	require.ErrorIs(t, err, nil)
	require.Equal(t, entries, got)

	empty, err := ParseToolSurface("")
	require.ErrorIs(t, err, nil)
	require.Empty(t, empty)
}

func TestToolAccess(t *testing.T) {
	tests := []struct {
		tool       string
		annotation string
		sets       []string
	}{
		{tool: "list_organizations", annotation: "read-only", sets: []string{"admin", "all", "default", "findings", "findings-write", "minimal"}},
		{tool: "nullify_search_findings", annotation: "read-only", sets: []string{"all", "default", "findings", "findings-write"}},
		{tool: "nullify_get_finding", annotation: "read-only", sets: []string{"all", "default", "findings", "findings-write"}},
		{tool: "get_security_trends", annotation: "read-only", sets: []string{"admin", "all", "default", "findings", "findings-write", "minimal"}},
		{tool: "nullify_get_fix_status", annotation: "read-only", sets: []string{"all", "default", "findings", "findings-write"}},
		{tool: "nullify_get_fix_diff", annotation: "read-only", sets: []string{"all", "default", "findings", "findings-write"}},
		{tool: "nullify_allowlist_finding", annotation: "destructive", sets: []string{"all", "default", "findings", "findings-write"}},
		{tool: "nullify_unallowlist_finding", annotation: "destructive", sets: []string{"all", "default", "findings", "findings-write"}},
		{tool: "nullify_create_ticket", annotation: "destructive", sets: []string{"all", "default", "findings", "findings-write"}},
		{tool: "nullify_fix_finding", annotation: "destructive", sets: []string{"all", "default", "findings", "findings-write"}},
		{tool: "nullify_submit_finding_feedback", annotation: "destructive", sets: []string{"all", "default", "findings", "findings-write"}},
		{tool: "nullify_archive_finding", annotation: "destructive", sets: []string{"all", "findings-write"}},
		{tool: "nullify_unarchive_finding", annotation: "destructive", sets: []string{"all", "findings-write"}},
		{tool: "nullify_mark_false_positive", annotation: "destructive", sets: []string{"all", "findings-write"}},
		{tool: "nullify_unmark_false_positive", annotation: "destructive", sets: []string{"all", "findings-write"}},
		{tool: "nullify_delete_ticket", annotation: "destructive", sets: []string{"all", "findings-write"}},
		{tool: "nullify_start_cloud_scan", annotation: "destructive", sets: []string{"all", "default"}},
		{tool: "nullify_create_threat_investigation", annotation: "destructive", sets: []string{"all", "default"}},
		{tool: "start_pentest", annotation: "destructive", sets: []string{"all"}},
		{tool: "stop_pentest_scan", annotation: "destructive", sets: []string{"all"}},
	}

	live := map[string]ToolEntry{}
	for _, e := range ToolSurface() {
		live[e.Name] = e
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			require.Equal(t, ToolEntry{Name: tt.tool, Annotation: tt.annotation, Sets: tt.sets}, live[tt.tool])
		})
	}
}
