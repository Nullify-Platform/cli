package logger

import (
	"runtime/debug"
	"strings"
)

// DevVersion is the version of a build that carries no release version, such
// as `go build` in a checkout.
const DevVersion = "dev"

// Version is never empty after package initialization, so cobra always adds
// the --version flag. It stays an uninitialized variable here because ldflags
// -X can only set a variable that has no initializer or a constant one.
func init() {
	Version = resolveVersion(Version, debug.ReadBuildInfo)
}

// resolveVersion returns the version set at build time through ldflags. A
// build without ldflags, such as `go install module@v1.2.3`, falls back to the
// module version that Go records in the binary, without its leading v to match
// release builds. Anything else is DevVersion.
func resolveVersion(
	ldflagsVersion string,
	readBuildInfo func() (*debug.BuildInfo, bool),
) string {
	if ldflagsVersion != "" {
		return ldflagsVersion
	}
	info, ok := readBuildInfo()
	if !ok || info == nil {
		return DevVersion
	}
	moduleVersion := info.Main.Version
	if moduleVersion == "" || moduleVersion == "(devel)" {
		return DevVersion
	}
	return strings.TrimPrefix(moduleVersion, "v")
}
