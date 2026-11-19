package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{a: "1.2.3", b: "1.2.3", want: 0},
		{a: "v1.2.3", b: "1.2.3", want: 0},
		{a: "1.2.3", b: "1.2.4", want: -1},
		{a: "1.10.0", b: "1.9.0", want: 1},
		{a: "2.0.0", b: "1.99.99", want: 1},
		{a: "1.3.0-rc.1", b: "1.3.0", want: -1},
		{a: "1.3.0-rc.2", b: "1.3.0-rc.10", want: -1},
		{a: "1.3.0-alpha", b: "1.3.0-alpha.1", want: -1},
		{a: "1.3.0-alpha.beta", b: "1.3.0-alpha.1", want: 1},
		{a: "1.3.0+build.5", b: "1.3.0", want: 0},
		{a: "1.2.4-0.20261119042408-3bd1e8c97fa3+dirty", b: "1.2.4", want: -1},
		{a: "1.2.4-0.20261119042408-3bd1e8c97fa3+dirty", b: "1.2.3", want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.a+" vs "+tt.b, func(t *testing.T) {
			a, ok := parseSemver(tt.a)
			require.True(t, ok)
			b, ok := parseSemver(tt.b)
			require.True(t, ok)
			require.Equal(t, tt.want, compareSemver(a, b))
		})
	}
}

func TestParseSemverRejectsNonReleases(t *testing.T) {
	for _, v := range []string{"", "dev", "unknown", "1.2", "1.2.3.4", "01.2.3", "1.2.3-", "1.2.3-rc..1", "3bd1e8c97fa3", "v1.2.x"} {
		t.Run(v, func(t *testing.T) {
			_, ok := parseSemver(v)
			require.False(t, ok)
		})
	}
}

func TestWriteUpdateAdvice(t *testing.T) {
	const oneLiner = "curl -sSfL https://raw.githubusercontent.com/Nullify-Platform/cli/main/install.sh | sh -s -- --version v1.3.0"

	tests := []struct {
		name        string
		current     string
		latestTag   string
		goos        string
		goarch      string
		contains    []string
		notContains []string
	}{
		{
			name: "same version", current: "1.3.0", latestTag: "v1.3.0", goos: "darwin", goarch: "arm64",
			contains:    []string{"You are running the latest version (1.3.0)"},
			notContains: []string{"new version", "curl"},
		},
		{
			name: "older on macOS", current: "1.2.3", latestTag: "v1.3.0", goos: "darwin", goarch: "arm64",
			contains:    []string{"A new version is available: 1.3.0 (current: 1.2.3)", oneLiner},
			notContains: []string{"brew", "tar xz"},
		},
		{
			name: "older on Linux", current: "1.2.3", latestTag: "v1.3.0", goos: "linux", goarch: "amd64",
			contains:    []string{"A new version is available", oneLiner, "~/.local/bin"},
			notContains: []string{"brew", "tar xz"},
		},
		{
			name: "older on Windows", current: "1.2.3", latestTag: "v1.3.0", goos: "windows", goarch: "amd64",
			contains: []string{
				"https://github.com/Nullify-Platform/cli/releases/download/v1.3.0/nullify_windows_amd64.zip",
				"Expand-Archive",
				"nullify.exe",
				"checksums.txt",
				oneLiner,
			},
			notContains: []string{".tar.gz", "brew"},
		},
		{
			name: "Windows on Arm uses the amd64 build", current: "1.2.3", latestTag: "v1.3.0", goos: "windows", goarch: "arm64",
			contains:    []string{"nullify_windows_amd64.zip"},
			notContains: []string{"nullify_windows_arm64"},
		},
		{
			name: "string inequality is not a new version", current: "1.10.0", latestTag: "v1.9.0", goos: "linux", goarch: "amd64",
			contains:    []string{"1.10.0", "newer than the latest release (1.9.0)"},
			notContains: []string{"new version is available", "curl"},
		},
		{
			name: "release candidate of the latest release", current: "1.3.0-rc.1", latestTag: "v1.3.0", goos: "linux", goarch: "amd64",
			contains: []string{"A new version is available: 1.3.0 (current: 1.3.0-rc.1)"},
		},
		{
			name: "dev build", current: "dev", latestTag: "v1.3.0", goos: "linux", goarch: "amd64",
			contains:    []string{"development build (dev)", "latest release is 1.3.0", oneLiner},
			notContains: []string{"latest version (dev)"},
		},
		{
			name: "make build stamped with a commit", current: "3bd1e8c97fa3-tainted", latestTag: "v1.3.0", goos: "darwin", goarch: "arm64",
			contains: []string{"development build (3bd1e8c97fa3-tainted)"},
		},
		{
			name: "no version", current: "", latestTag: "v1.3.0", goos: "darwin", goarch: "arm64",
			contains: []string{"development build (unknown)"},
		},
		{
			name: "other OS", current: "1.2.3", latestTag: "v1.3.0", goos: "freebsd", goarch: "amd64",
			contains:    []string{"no release build for freebsd/amd64", "https://github.com/Nullify-Platform/cli/releases/tag/v1.3.0"},
			notContains: []string{"install.sh"},
		},
		{
			name: "other architecture", current: "1.2.3", latestTag: "v1.3.0", goos: "linux", goarch: "386",
			contains:    []string{"no release build for linux/386"},
			notContains: []string{"install.sh"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			require.NoError(t, writeUpdateAdvice(&out, tt.current, tt.latestTag, tt.goos, tt.goarch))
			for _, s := range tt.contains {
				require.Contains(t, out.String(), s)
			}
			for _, s := range tt.notContains {
				require.NotContains(t, out.String(), s)
			}
		})
	}
}

func TestWriteUpdateAdviceRejectsAnUnexpectedTag(t *testing.T) {
	var out bytes.Buffer
	err := writeUpdateAdvice(&out, "1.2.3", "nightly", "linux", "amd64")
	require.ErrorContains(t, err, `"nightly"`)
	require.Empty(t, out.String())
}
