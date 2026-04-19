package manifest

// Gemfile.lock (RubyGems) — bespoke line-oriented format.
//
// Shape (abbreviated):
//   GEM
//     remote: https://rubygems.org/
//     specs:
//       activerecord (7.1.3)
//         activemodel (= 7.1.3)
//         activesupport (= 7.1.3)
//       i18n (1.14.1)
//         concurrent-ruby (~> 1.0)
//   PLATFORMS
//     x86_64-linux
//   DEPENDENCIES
//     rails
//
// We care about the GEM section, specifically lines under `specs:`
// where the name + pinned version sit at indent-level 4. Transitive
// deps listed under a parent spec are at indent-level 6; we skip them
// because they're NOT pinned (only version constraints), and we'll
// see their pinned version when they appear as top-level specs.

import (
	"bufio"
	"bytes"
	"strings"
)

type GemfileLock struct{}

func NewGemfileLock() Parser { return &GemfileLock{} }

func (g *GemfileLock) Name() string { return "Gemfile.lock" }

func (g *GemfileLock) Matches(path string) bool {
	return HasSuffixI(path, "Gemfile.lock")
}

func (g *GemfileLock) Parse(data []byte, path string) ([]Entry, error) {
	out := []Entry{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	inGemSpecs := false
	for scanner.Scan() {
		raw := scanner.Text()
		// Track section boundaries. GEM section holds spec entries;
		// DEPENDENCIES / PLATFORMS / BUNDLED WITH don't.
		if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") {
			inGemSpecs = false
			continue
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "specs:" {
			inGemSpecs = true
			continue
		}
		if !inGemSpecs {
			continue
		}
		// Indent-4 lines are pinned spec entries:
		//   "    activerecord (7.1.3)"
		// Indent-6 lines are transitive-dep declarations:
		//   "      activemodel (= 7.1.3)"
		// Count leading spaces to distinguish.
		leading := 0
		for i := 0; i < len(raw); i++ {
			if raw[i] != ' ' {
				break
			}
			leading++
		}
		if leading != 4 {
			continue
		}
		// Parse "name (version)".
		openParen := strings.Index(trimmed, " (")
		if openParen < 0 {
			continue
		}
		closeParen := strings.LastIndex(trimmed, ")")
		if closeParen <= openParen+2 {
			continue
		}
		name := trimmed[:openParen]
		version := trimmed[openParen+2 : closeParen]
		if name == "" || version == "" {
			continue
		}
		out = append(out, Entry{
			Ecosystem: "rubygems",
			Name:      name,
			Version:   version,
			File:      path,
			// We can't tell direct-vs-transitive without cross-checking
			// DEPENDENCIES section. Leave false.
			Direct: false,
		})
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	return out, nil
}
