package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDASTFindingSeverityJSONRoundTrip(t *testing.T) {
	// The wire representation must remain the same lowercase strings as before
	// the field was changed from string to the typed Severity enum.
	raw := `{"id":"f1","scanner":"dast","title":"SQLi","severity":"critical","appType":"rest","cwe":"CWE-89","solution":"fix it","rest":{}}`

	var finding DASTFinding
	require.NoError(t, json.Unmarshal([]byte(raw), &finding))
	require.Equal(t, SeverityCritical, finding.Severity)

	out, err := json.Marshal(finding)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	require.Equal(t, "critical", got["severity"])
}

func TestSeverityIsValid(t *testing.T) {
	require.True(t, SeverityCritical.IsValid())
	require.True(t, SeverityHigh.IsValid())
	require.True(t, SeverityMedium.IsValid())
	require.True(t, SeverityLow.IsValid())
	require.True(t, SeverityInfo.IsValid())
	require.False(t, Severity("bogus").IsValid())
}

func TestParseSeverity(t *testing.T) {
	sev, err := ParseSeverity("high")
	require.NoError(t, err)
	require.Equal(t, SeverityHigh, sev)
	require.Equal(t, "high", sev.String())

	_, err = ParseSeverity("nope")
	require.Error(t, err)
}

func TestAuthMethodJSONRoundTrip(t *testing.T) {
	raw := `{"method":"basic","username":"u"}`

	var cfg AuthConfig
	require.NoError(t, json.Unmarshal([]byte(raw), &cfg))
	require.Equal(t, AuthMethodBasic, cfg.Method)

	out, err := json.Marshal(cfg)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	require.Equal(t, "basic", got["method"])
}

func TestParseAuthMethod(t *testing.T) {
	m, err := ParseAuthMethod("oauth")
	require.NoError(t, err)
	require.Equal(t, AuthMethodOAuth, m)

	_, err = ParseAuthMethod("telepathy")
	require.Error(t, err)
}
