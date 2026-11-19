package cmd

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

func TestBuildThreatInputSeverity(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    *string
		wantErr string
	}{
		{name: "lower case is sent upper case", args: []string{"--severity", "critical"}, want: ptr("CRITICAL")},
		{name: "mixed case", args: []string{"--severity", "High"}, want: ptr("HIGH")},
		{name: "upper case", args: []string{"--severity", "MEDIUM"}, want: ptr("MEDIUM")},
		{name: "low", args: []string{"--severity", "low"}, want: ptr("LOW")},
		{name: "informational", args: []string{"--severity", "informational"}, want: ptr("INFORMATIONAL")},
		{name: "surrounding spaces", args: []string{"--severity", " low "}, want: ptr("LOW")},
		{name: "omitted", args: nil, want: nil},
		{name: "unknown severity", args: []string{"--severity", "severe"}, wantErr: `invalid --severity "severe"`},
		{name: "server sentinel is not a choice", args: []string{"--severity", "unknown"}, wantErr: "critical, high, medium, low, informational"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := pflag.NewFlagSet("threat create", pflag.ContinueOnError)
			addThreatCreateFlags(flags)
			require.NoError(t, flags.Parse(append([]string{"--title", "Log4Shell"}, tt.args...)))

			in, err := buildThreatInput(flags)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "Log4Shell", in.Title)
			require.Equal(t, tt.want, in.Severity)
		})
	}
}

func TestBuildThreatInputFields(t *testing.T) {
	flags := pflag.NewFlagSet("threat create", pflag.ContinueOnError)
	addThreatCreateFlags(flags)
	require.NoError(t, flags.Parse([]string{
		"--title", "CVE sweep",
		"--cvss", "9.8",
		"--cve-ids", "CVE-2021-44228, CVE-2021-45046,",
		"--keywords", "log4j",
	}))

	in, err := buildThreatInput(flags)
	require.NoError(t, err)
	require.Equal(t, []string{"CVE-2021-44228", "CVE-2021-45046"}, in.CveIds)
	require.InDelta(t, 9.8, *in.Cvss, 0.0001)
	require.Equal(t, "log4j", *in.Keywords)
	require.Nil(t, in.Description)

	bad := pflag.NewFlagSet("threat create", pflag.ContinueOnError)
	addThreatCreateFlags(bad)
	require.NoError(t, bad.Parse([]string{"--title", "x", "--cvss", "high"}))
	_, err = buildThreatInput(bad)
	require.ErrorContains(t, err, `invalid --cvss "high"`)
}

func ptr(s string) *string { return &s }
