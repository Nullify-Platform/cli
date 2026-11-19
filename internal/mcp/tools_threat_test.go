package mcp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The server stores a threat investigation's severity as sent and filters on
// its upper-case enum, so the tool sends the severity upper case.
func TestCreateThreatInvestigationSendsUpperCaseSeverity(t *testing.T) {
	s, rec := newTestServer(t, orgsFor(map[string]string{"a": "1"}, "a"))

	res := callTool(t, s, "nullify_create_threat_investigation", map[string]any{
		"title":    "Log4Shell",
		"severity": "critical",
	})

	require.Nil(t, res.Error)
	require.False(t, res.Result.IsError, res.Result.Content)
	bodies := rec.bodiesTo("/manager/threat-investigations")
	require.Len(t, bodies, 1)
	require.Contains(t, bodies[0], `"severity":"CRITICAL"`)
}
