package manifest

// package-lock.json (npm v2/v3) parser.
//
// Shape summary:
//   {
//     "lockfileVersion": 2 | 3,
//     "packages": {
//       "": {...root...},
//       "node_modules/lodash": {"version": "4.17.21", "dev": false, ...},
//       "node_modules/@foo/bar": {"version": "1.0.0", ...}
//     },
//     "dependencies": {...v1-style tree...}  // v2 only, ignored here
//   }
//
// We read the "packages" map and skip entries whose key doesn't start
// with "node_modules/" (the empty-key root package isn't a dependency
// we care about). Name is derived from the key suffix.

import (
	"encoding/json"
	"strings"
)

type NPMLock struct{}

func NewNPMLock() Parser { return &NPMLock{} }

func (n *NPMLock) Name() string { return "package-lock.json" }

func (n *NPMLock) Matches(path string) bool {
	return HasSuffixI(path, "package-lock.json")
}

type npmLockFile struct {
	LockfileVersion int                             `json:"lockfileVersion"`
	Packages        map[string]npmLockPackageEntry `json:"packages"`
}

type npmLockPackageEntry struct {
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
}

func (n *NPMLock) Parse(data []byte, path string) ([]Entry, error) {
	var lock npmLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(lock.Packages))
	for key, pkg := range lock.Packages {
		if key == "" {
			continue // root package metadata, not a dependency
		}
		name := stripNodeModulesPrefix(key)
		if name == "" || pkg.Version == "" {
			continue
		}
		out = append(out, Entry{
			Ecosystem: "npm",
			Name:      name,
			Version:   pkg.Version,
			File:      path,
			// Lockfile doesn't reliably expose "declared by root vs
			// transitive"; leave Direct false. The deps-analyze
			// workflow treats every change as worth inspecting.
			Direct: false,
		})
	}
	return out, nil
}

// stripNodeModulesPrefix turns the lockfile key shape into the npm
// package name. Handles nested node_modules (transitive conflicts) by
// taking only the last node_modules/ segment:
//   "node_modules/lodash"                       → "lodash"
//   "node_modules/a/node_modules/lodash"        → "lodash"
//   "node_modules/@scope/pkg"                   → "@scope/pkg"
//   "node_modules/a/node_modules/@scope/pkg"    → "@scope/pkg"
func stripNodeModulesPrefix(key string) string {
	const prefix = "node_modules/"
	idx := strings.LastIndex(key, prefix)
	if idx < 0 {
		return ""
	}
	return key[idx+len(prefix):]
}
