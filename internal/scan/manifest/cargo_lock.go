package manifest

// Cargo.lock (Rust) — TOML format with repeated `[[package]]` tables.
// Each entry has `name`, `version`, and optionally `source`. Workspace
// members (no `source`) are the repo's own crates and not interesting
// for vuln lookup; we skip them.
//
// Rather than pull in a full TOML parser, we hand-roll a tiny scanner
// since the Cargo.lock shape is well-behaved and we only need two
// fields per package.

import (
	"bufio"
	"bytes"
	"strings"
)

type CargoLock struct{}

func NewCargoLock() Parser { return &CargoLock{} }

func (c *CargoLock) Name() string { return "Cargo.lock" }

func (c *CargoLock) Matches(path string) bool {
	return HasSuffixI(path, "Cargo.lock")
}

func (c *CargoLock) Parse(data []byte, path string) ([]Entry, error) {
	out := []Entry{}
	scanner := bufio.NewScanner(bytes.NewReader(data))

	inPackage := false
	var name, version, source string

	flush := func() {
		defer func() { name, version, source = "", "", "" }()
		// Workspace member: no source → skip (the vuln-database has no
		// record of the repo's own crates).
		if source == "" || name == "" || version == "" {
			return
		}
		out = append(out, Entry{
			Ecosystem: "crates.io",
			Name:      name,
			Version:   version,
			File:      path,
			// Cargo.lock doesn't mark direct-vs-transitive; the root
			// manifest would, but we're not reading it here.
			Direct: false,
		})
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "[[package]]":
			if inPackage {
				flush()
			}
			inPackage = true
		case strings.HasPrefix(line, "[") && line != "[[package]]":
			// New non-package section — flush any pending package.
			if inPackage {
				flush()
				inPackage = false
			}
		case inPackage:
			switch {
			case strings.HasPrefix(line, "name = "):
				name = stripTOMLString(line[len("name = "):])
			case strings.HasPrefix(line, "version = "):
				version = stripTOMLString(line[len("version = "):])
			case strings.HasPrefix(line, "source = "):
				source = stripTOMLString(line[len("source = "):])
			}
		}
	}
	if inPackage {
		flush()
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// stripTOMLString removes surrounding quotes from a TOML string value.
// Doesn't handle escapes — name/version are well-formed package
// identifiers, never contain quotes.
func stripTOMLString(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ",")
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
