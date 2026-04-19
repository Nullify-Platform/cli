package manifest

// Go module: parse go.sum rather than go.mod.
//
// go.sum lists every version of every module the build ever saw, one
// module-version per line. go.mod lists the _declared_ requirements,
// which is a smaller set but doesn't include transitive resolutions.
// For malware-analysis purposes we want what actually got pulled in;
// go.sum is the right source.
//
// Line shape: "<module path> <version> h1:<hash>"
// Dup lines per version (one for "h1:" hash of zip, one for "/go.mod"
// hash) — dedupe by (path, version).

import (
	"bufio"
	"bytes"
	"strings"
)

type GoMod struct{}

func NewGoMod() Parser { return &GoMod{} }

func (g *GoMod) Name() string { return "go.sum" }

func (g *GoMod) Matches(path string) bool {
	return HasSuffixI(path, "go.sum")
}

func (g *GoMod) Parse(data []byte, path string) ([]Entry, error) {
	seen := map[string]bool{}
	out := []Entry{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// go.sum lines can be long; default buffer is 64k. Bump to 1MB so
	// pathological monorepo go.sum files don't truncate.
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		modPath := fields[0]
		version := fields[1]
		// Skip "/go.mod" hash rows — same (path, version) info as the
		// zip row, dedupe would catch it but the check is cheap.
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}
		key := modPath + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Entry{
			Ecosystem: "go",
			Name:      modPath,
			Version:   version,
			File:      path,
			// go.sum doesn't distinguish direct vs transitive; leave
			// Direct false + document the limitation.
			Direct: false,
		})
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	return out, nil
}
