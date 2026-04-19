// Package manifest parses lockfiles + manifests to produce a flat
// (ecosystem, name, version) list that nullify deps analyze compares
// between two commits.
//
// Each ecosystem implementation lives in its own file. ParseAll
// dispatches by filename — callers pass a list of paths (usually
// computed from a git diff) and receive every parseable entry.
// Unknown paths are silently skipped; there's no "no parser for X"
// error because most repos contain files that aren't lockfiles.
package manifest

import (
	"errors"
	"path/filepath"
	"strings"
)

// Entry is one parsed dependency record. Ecosystem matches the
// vdb_ecosystem enum values so we don't transform names between the CLI
// and vuln-database.
type Entry struct {
	Ecosystem string
	Name      string
	Version   string
	// File is the repo-relative path this entry came from — useful for
	// error reporting and for scpm's audit log.
	File string
	// Direct is true when the lockfile declares the package at the top
	// level of its "dependencies" block. False for transitive deps.
	// Some formats (go.sum, Cargo.lock) don't distinguish; in that
	// case we leave it false and document the limitation per-parser.
	Direct bool
}

// Parser is the per-file-format interface. Implementations are
// registered in parsers.go. Parse is given the file's bytes + its
// repo-relative path; it returns a flat Entry slice or an error.
type Parser interface {
	Name() string
	Matches(repoRelPath string) bool
	Parse(data []byte, repoRelPath string) ([]Entry, error)
}

// ErrNoParser is returned when no registered parser matches a path.
// ParseAll uses errors.Is to filter it out silently — the CLI
// workflow doesn't need to surface "we don't know what this file is."
var ErrNoParser = errors.New("no parser matched")

// ParseAll applies every registered parser to the given paths + data
// slice. The slice is (path, contents) pairs; missing entries are
// skipped. Returns a flat slice of Entry + a map of path→parser-error
// for entries the parser matched but couldn't parse (malformed
// lockfile, partial write, etc.).
type File struct {
	Path string
	Data []byte
}

type Result struct {
	Entries []Entry
	Errors  map[string]error
}

func ParseAll(parsers []Parser, files []File) Result {
	out := Result{Errors: map[string]error{}}
	for _, f := range files {
		for _, p := range parsers {
			if !p.Matches(f.Path) {
				continue
			}
			entries, err := p.Parse(f.Data, f.Path)
			if err != nil {
				out.Errors[f.Path] = err
				continue
			}
			out.Entries = append(out.Entries, entries...)
			break // first matching parser wins; don't double-count
		}
	}
	return out
}

// DefaultParsers returns the full set in a stable order. Sequence
// matters only for tiebreaking when two parsers claim the same path
// (shouldn't happen with the current set).
func DefaultParsers() []Parser {
	return []Parser{
		NewNPMLock(),
		NewPyPILock(),
		NewGoMod(),
		NewCargoLock(),
		NewGemfileLock(),
	}
}

// HasSuffixI is a case-insensitive suffix match shared by every parser.
// Saves every Matches() from importing strings directly.
func HasSuffixI(path, suffix string) bool {
	return strings.EqualFold(filepath.Base(path), suffix)
}
