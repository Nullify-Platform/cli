package logger

import (
	"runtime/debug"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	buildInfo := func(version string) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Version: version}}, true
		}
	}
	noBuildInfo := func() (*debug.BuildInfo, bool) { return nil, false }

	tests := []struct {
		name      string
		ldflags   string
		buildInfo func() (*debug.BuildInfo, bool)
		want      string
	}{
		{name: "ldflags version wins", ldflags: "1.4.0", buildInfo: buildInfo("v1.3.0"), want: "1.4.0"},
		{name: "go install module version", buildInfo: buildInfo("v1.3.0"), want: "1.3.0"},
		{name: "go install pseudo-version", buildInfo: buildInfo("v1.3.1-0.20261119000000-abcdef123456"), want: "1.3.1-0.20261119000000-abcdef123456"},
		{name: "local build without a module version", buildInfo: buildInfo("(devel)"), want: "dev"},
		{name: "empty module version", buildInfo: buildInfo(""), want: "dev"},
		{name: "no build info", buildInfo: noBuildInfo, want: "dev"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVersion(tt.ldflags, tt.buildInfo); got != tt.want {
				t.Errorf("resolveVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVersionIsNeverEmpty(t *testing.T) {
	if Version == "" {
		t.Fatal("Version is empty, so cobra adds no --version flag")
	}
}
