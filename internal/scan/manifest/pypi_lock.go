package manifest

// PyPI: requirements.txt parser. Handles the PEP 440 "foo==1.2.3" shape
// + common comment / editable-install forms by skipping them.
//
// We intentionally target requirements.txt (rather than poetry.lock /
// uv.lock) because:
//   - Most security-scanning pipelines emit pinned requirements.txt
//     regardless of the dev tooling, so parsing this covers the
//     widest surface with the least code.
//   - poetry.lock / uv.lock / Pipfile.lock all have richer formats
//     (TOML / custom) that are follow-up work.
//
// Lines we recognise as pinned deps:
//   foo==1.2.3
//   foo==1.2.3  # comment
//   foo ~= 1.2   # skipped (non-exact pin — not useful for analysis)
// Skipped: comments, blank lines, -r/-e directives, git+ URLs, wheels.

import (
	"bufio"
	"bytes"
	"strings"
)

type PyPILock struct{}

func NewPyPILock() Parser { return &PyPILock{} }

func (p *PyPILock) Name() string { return "requirements.txt" }

func (p *PyPILock) Matches(path string) bool {
	return HasSuffixI(path, "requirements.txt") ||
		HasSuffixI(path, "requirements-dev.txt") ||
		HasSuffixI(path, "requirements_prod.txt")
}

func (p *PyPILock) Parse(data []byte, path string) ([]Entry, error) {
	out := []Entry{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments.
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// Skip directive lines (-r, -e, --index-url, etc.).
		if strings.HasPrefix(line, "-") {
			continue
		}
		// Skip URL-based deps (git+, https://).
		if strings.HasPrefix(line, "git+") || strings.HasPrefix(line, "http") {
			continue
		}
		// Only exact pins. `==` is the PEP 440 equality operator; we
		// want the left side as name, right side as version.
		eq := strings.Index(line, "==")
		if eq < 0 {
			continue
		}
		name := strings.TrimSpace(line[:eq])
		ver := strings.TrimSpace(line[eq+2:])
		// Handle `name==1.2.3; python_version >= "3.8"` environment
		// markers — strip everything after the first semicolon.
		if semi := strings.Index(ver, ";"); semi >= 0 {
			ver = strings.TrimSpace(ver[:semi])
		}
		// Strip wheel/hash suffixes like `==1.2.3 --hash=sha256:...`.
		if sp := strings.IndexByte(ver, ' '); sp >= 0 {
			ver = ver[:sp]
		}
		// Normalise the PyPI name per PEP 503 — lower-case, hyphens
		// and underscores interchangeable. We store the raw name, but
		// downstream vuln-database treats "requests" and "Requests"
		// as identical, so exact-casing matters less than completeness.
		name = strings.TrimSpace(name)
		if name == "" || ver == "" {
			continue
		}
		// Strip extras: `requests[security]==2.32.3` → "requests".
		if bracket := strings.Index(name, "["); bracket >= 0 {
			name = name[:bracket]
		}
		out = append(out, Entry{
			Ecosystem: "pypi",
			Name:      name,
			Version:   ver,
			File:      path,
			Direct:    true, // requirements.txt entries are all explicitly declared
		})
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	return out, nil
}
